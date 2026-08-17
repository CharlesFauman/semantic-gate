#!/usr/bin/env python3
"""Generic coordinator adapter around the deterministic gate engine."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import re
from typing import Any

from .authorization import HMACAuthorizationAuthority, SQLiteAuthorizationStore
from .engine import ApprovalRejected, GatewayEngine, ToolRegistry
from .engine import RecordingNotifier


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
    def __init__(self, policy: dict, *, approval_key: bytes, clock, notifier=None, authorization_key: bytes | None = None, authorization_authority: Any | None = None, authorization_store: SQLiteAuthorizationStore | None = None):
        if authorization_key is not None and authorization_authority is not None: raise ValueError("provide authorization_key or authorization_authority, not both")
        self.clock = clock
        self.verifier = HostApprovalVerifier(approval_key)
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
            authorization_authority=authorization_authority or (HMACAuthorizationAuthority(authorization_key,issuer="semantic-gate-coordinator") if authorization_key is not None else None),
            authorization_store=authorization_store,
            clock=self.clock,
        )

    def list_actions(self, principal: str):
        return self.engine.list_actions(principal=principal)

    def explain_action(self, action: str, principal: str):
        return self.engine.explain_action(action, principal=principal)

    def request_action(self, **kwargs):
        return self.engine.request_action(**kwargs)

    def get_request(self, request_id: str, requester: str | None = None):
        if requester is None:
            return self.engine.get_request(request_id)
        return self.engine.get_request_for(request_id, requester=requester)

    def cancel_request(self, request_id: str, requester: str):
        return self.engine.cancel_request(request_id, requester=requester)

    def approve_request(self, request_id: str, actor: str, assurance: str = "ask", evidence_id: str | None = None, provenance: dict | None = None, expires_at: int | None = None):
        if assurance not in {"ask","step_up"}:
            raise ApprovalRejected("approval assurance is invalid")
        if evidence_id is not None and (not isinstance(evidence_id,str) or not evidence_id): raise ApprovalRejected("approval evidence_id is invalid")
        provenance=dict(provenance or {"transport":"hmac-host"})
        if provenance=={"transport":"hmac-host"}: pass
        elif set(provenance)=={"transport","key_id","signed_at","signature_sha256"} and provenance["transport"]=="ed25519" and isinstance(provenance["key_id"],str) and bool(provenance["key_id"]) and type(provenance["signed_at"]) is int and isinstance(provenance["signature_sha256"],str) and re.fullmatch(r"[0-9a-f]{64}",provenance["signature_sha256"]): pass
        else: raise ApprovalRejected("approval provenance is invalid")
        request = self.engine.get_request(request_id)
        approval = next(
            gate for gate in request["gates"]
            if gate["kind"] == "approval" and gate["status"] == "waiting"
        )
        now=int(self.clock()); ttl = int(approval["evidence"]["ttl_seconds"])
        if expires_at is not None and (type(expires_at) is not int or expires_at<=now): raise ApprovalRejected("approval expiry is invalid")
        bounded_expiry=min(now+ttl,expires_at) if expires_at is not None else now+ttl
        evidence = {
            "evidence_id": evidence_id or "approval_" + secrets.token_hex(16),
            "request_id": request_id,
            "request_hash": request["request_hash"],
            "approval_gate_id": approval["id"],
            "actor": actor,
            "decision": "approve",
            "assurance": assurance,
            "expires_at": bounded_expiry,
            "provenance": provenance,
        }
        evidence["signature"] = self.verifier.sign(evidence)
        return self.engine.ingest_trusted_approval(request_id, evidence)
