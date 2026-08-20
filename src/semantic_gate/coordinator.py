#!/usr/bin/env python3
"""Generic coordinator adapter around the deterministic gate engine."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

from . import autoapproval
from .catalog import validate_catalog
from .engine import ApprovalRejected, GatewayEngine, RecordingNotifier, ToolRegistry


class HostApprovalVerifier:
    def __init__(self, key: bytes):
        if len(key) < 32:
            raise ValueError("approval key must contain at least 32 bytes")
        self.key = bytes(key)

    @staticmethod
    def _body(evidence: dict) -> bytes:
        body = {key: value for key, value in evidence.items() if key != "signature"}
        return json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

    def sign(self, evidence: dict) -> str:
        return hmac.new(self.key, self._body(evidence), hashlib.sha256).hexdigest()

    def verify(self, evidence: dict, request: dict) -> bool:
        supplied = evidence.get("signature")
        assurance=evidence.get("assurance")
        required=request.get("effective_control","ask")
        ranks={"ask":1,"step_up":2}
        return (isinstance(supplied,str) and assurance in ranks and required in ranks
                and ranks[assurance]>=ranks[required]
                and hmac.compare_digest(supplied,self.sign(evidence)))


class CoreBackend:
    APPROVAL_ABSOLUTE_CAP_SECONDS = 6 * 60 * 60
    TERMINAL_STATES = frozenset({"blocked", "cancelled", "simulated", "executed", "failed", "expired", "denied"})

    def __init__(self, policy: dict, *, approval_key: bytes, clock, notifier=None, auto_approval=None, auto_approval_path_resolver=None, catalog=None):
        self.clock = clock
        self.verifier = HostApprovalVerifier(approval_key)
        self.auto_approval = auto_approval
        self.catalog = None if catalog is None else validate_catalog(catalog)
        if auto_approval is not None and auto_approval.global_simulation_rule is not None and self.catalog is None:
            raise ValueError("a standing auto-approval rule requires the authoritative action catalogue")
        self._auto_approval_path_resolver = auto_approval_path_resolver
        self._decision_challenges: dict[str,dict] = {}
        self._trusted_nodes: dict[str,str] = {}
        registry = ToolRegistry()
        actions = set(policy["workflows"])

        def precheck(arguments: dict) -> dict:
            action = arguments.get("action")
            return {"eligible": action in actions, "checked_at": int(self.clock())}

        registry.register_read("semantic.policy_precheck", precheck)
        self.engine = GatewayEngine(
            policy,
            registry=registry,
            notifier=notifier or RecordingNotifier(),
            approval_verifier=self.verifier,
            execution_authority=None,
            clock=self.clock,
        )

    @property
    def execution_enabled(self) -> bool:
        """The live execution flag of the loaded policy, never a cached copy."""
        return self.engine.policy["execution_enabled"] is True

    def _forget(self, request_id: str) -> None:
        """Purge challenge and trusted-node bindings for one request."""
        self._decision_challenges.pop(request_id, None)
        self._trusted_nodes.pop(request_id, None)

    def _observe_state(self, request: dict) -> dict:
        """Purge binding state whenever a terminal or expired request is observed."""
        request_id = request.get("request_id")
        if not isinstance(request_id, str):
            return request
        if request.get("state") in self.TERMINAL_STATES:
            self._forget(request_id)
            return request
        challenge = self._decision_challenges.get(request_id)
        if challenge is not None and challenge["expires_at"] <= int(self.clock()):
            self._forget(request_id)
        return request

    def list_actions(self, principal: str):
        return self.engine.list_actions(principal=principal)

    def explain_action(self, action: str, principal: str):
        return self.engine.explain_action(action, principal=principal)

    def request_action(self, **kwargs):
        request=self.engine.request_action(**kwargs)
        trusted=kwargs.get("trusted_context")
        node=trusted.get("node") if isinstance(trusted,dict) else None
        if isinstance(node,str) and node and request.get("state") not in self.TERMINAL_STATES:
            self._trusted_nodes[request["request_id"]]=node
        if request.get("state")=="waiting_for_approval":
            notification=next((gate for gate in request["gates"] if gate["kind"]=="notify"),None)
            evidence=(notification or {}).get("evidence") or {}
            delivered_at=evidence.get("delivered_at") if evidence.get("delivered") is True else None
            if type(delivered_at) is int:
                challenge=self.mark_notification_delivered(request["request_id"],delivered_at=delivered_at)
                if challenge is not None:
                    request["approval_challenge"]=challenge
        return request

    def mark_notification_delivered(self, request_id: str, *, delivered_at: int) -> dict | None:
        request=self.engine.get_request(request_id)
        if request.get("state")!="waiting_for_approval":
            return None
        now=int(self.clock())
        if type(delivered_at) is not int or delivered_at<request["created_at"] or delivered_at>now:
            raise ApprovalRejected("notification delivery time is invalid")
        approval=next(gate for gate in request["gates"] if gate["kind"]=="approval" and gate["status"]=="waiting")
        deadline=min(
            delivered_at+int(approval["evidence"]["ttl_seconds"]),
            request["created_at"]+self.APPROVAL_ABSOLUTE_CAP_SECONDS,
        )
        if deadline<=now:
            return None
        challenge={
            "request_id":request["request_id"],
            "request_hash":request["request_hash"],
            "approval_gate_id":approval["id"],
            "expires_at":deadline,
        }
        existing=self._decision_challenges.get(request_id)
        if existing is not None and existing!=challenge:
            raise ApprovalRejected("decision challenge is already bound to a different delivery")
        self._decision_challenges[request_id]=challenge
        return dict(challenge)

    def _with_challenge(self, request: dict) -> dict:
        if "approval_challenge" in request:
            return request
        challenge = self.approval_challenge(request["request_id"])
        return request if challenge is None else {**request, "approval_challenge": challenge}

    def auto_approval_decision(self, request: dict, *, node: str | None = None, paused: bool = False, disabled_rules=()) -> dict | None:
        """Dry-runnable, side-effect-free auto-approval evaluation for one exact request."""
        if self.auto_approval is None:
            return None
        return autoapproval.evaluate(
            self._with_challenge(request),
            policy=self.auto_approval,
            now=int(self.clock()),
            node=node or self._trusted_nodes.get(request.get("request_id")),
            policy_version=self.auto_approval.version,
            paused=paused,
            disabled_rules=disabled_rules,
            path_resolver=self._auto_approval_path_resolver,
            catalogue=self.catalog,
            execution_enabled=self.execution_enabled,
        )

    def auto_approve(self, request_id: str, decision: dict, *, node: str | None = None) -> tuple[dict, dict, dict]:
        """Ingest single-request auto-approval evidence through the ordinary approval gate."""
        if self.auto_approval is None:
            raise ApprovalRejected("auto-approval policy is not configured")
        if not isinstance(decision, dict) or not decision.get("matched"):
            raise ApprovalRejected("auto-approval decision did not match a declared rule")
        request = self._with_challenge(self.engine.get_request(request_id))
        fresh = self.auto_approval_decision(request, node=node)
        if fresh is None or not fresh["matched"]:
            raise ApprovalRejected(f"auto-approval no longer matches: {(fresh or {}).get('reason_code', 'unavailable')}")
        if fresh["evidence_binding"] != decision["evidence_binding"]:
            raise ApprovalRejected("auto-approval binding changed since the match")
        evidence = autoapproval.approval_evidence(fresh, request)
        commit = request.get("parameters", {}).get("commit")
        if not autoapproval.commit_binding_valid(evidence, commit=commit if isinstance(commit, str) else None):
            raise ApprovalRejected("auto-approval commit identity changed since the match")
        evidence["signature"] = self.verifier.sign(evidence)
        decided = self.engine.ingest_trusted_approval(request_id, evidence)
        self._forget(request_id)
        return decided, evidence, autoapproval.audit_metadata(fresh, request)

    def approval_challenge(self, request_id: str) -> dict | None:
        challenge=self._decision_challenges.get(request_id)
        return None if challenge is None else dict(challenge)

    def get_request(self, request_id: str, requester: str | None = None):
        if requester is None:
            return self._observe_state(self.engine.get_request(request_id))
        return self._observe_state(self.engine.get_request_for(request_id, requester=requester))

    def cancel_request(self, request_id: str, requester: str):
        cancelled = self.engine.cancel_request(request_id, requester=requester)
        self._forget(request_id)
        return cancelled

    def _decision(self, request_id: str, challenge: dict) -> tuple[dict, dict]:
        request = self.engine.get_request(request_id)
        if request["state"] != "waiting_for_approval":
            raise ApprovalRejected("request is not awaiting approval")
        if not isinstance(challenge, dict) or set(challenge) != {"request_id", "request_hash", "approval_gate_id", "expires_at"}:
            raise ApprovalRejected("decision challenge is incomplete")
        approval = next(gate for gate in request["gates"] if gate["kind"] == "approval" and gate["status"] == "waiting")
        expected = self._decision_challenges.get(request_id)
        if expected is None:
            raise ApprovalRejected("decision challenge is unavailable")
        if challenge != expected:
            raise ApprovalRejected("decision challenge does not match the waiting request")
        if challenge["expires_at"] <= int(self.clock()):
            raise ApprovalRejected("decision challenge is expired")
        return request, approval

    def approve_request(self, request_id: str, actor: str, challenge: dict):
        request, approval = self._decision(request_id, challenge)
        if request.get("effective_control") == "step_up":
            raise ApprovalRejected("step-up requires an independent stronger transport")
        evidence = {
            "evidence_id": "approval_" + secrets.token_hex(16),
            "request_id": request_id,
            "request_hash": request["request_hash"],
            "approval_gate_id": approval["id"],
            "actor": actor,
            "decision": "approve",
            "assurance": "ask",
            "expires_at": challenge["expires_at"],
        }
        evidence["signature"] = self.verifier.sign(evidence)
        decided=self.engine.ingest_trusted_approval(request_id,evidence)
        self._forget(request_id)
        return decided

    def deny_request(self, request_id: str, actor: str, challenge: dict):
        request, approval = self._decision(request_id, challenge)
        decided=self.engine.ingest_trusted_denial(request_id, {
            "request_id": request_id,
            "request_hash": request["request_hash"],
            "approval_gate_id": approval["id"],
            "actor": actor,
            "decision": "deny",
            "expires_at": challenge["expires_at"],
            "decided_at": int(self.clock()),
        })
        self._forget(request_id)
        return decided
