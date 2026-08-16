#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from semantic_gate.engine import (  # noqa: E402
    ApprovalRejected,
    ExecutionAuthority,
    GatePolicyError,
    GatewayEngine,
    RecordingNotifier,
    ToolRegistry,
    load_policy,
)


class Clock:
    def __init__(self, now: int = 1_700_000_000):
        self.now = now

    def __call__(self) -> int:
        return self.now


class ExactApprovalVerifier:
    """Test-only stand-in for a trusted human approval surface."""

    def verify(self, evidence: dict, request: dict) -> bool:
        return (
            evidence.get("trusted_test_evidence") is True
            and evidence.get("actor") == "test-human"
            and evidence.get("request_hash") == request["request_hash"]
        )


class DeliveredNotifier:
    def __init__(self) -> None:
        self.events = []

    def notify(self, request: dict, gate: dict) -> dict:
        event = {
            "notification_id": f"delivered-{request['request_id']}-{gate['id']}",
            "request_id": request["request_id"],
            "request_hash": request["request_hash"],
            "notification_gate_id": gate["id"],
            "recipient": gate["recipient"],
            "template_hash": hashlib.sha256(gate["template"].encode("utf-8")).hexdigest(),
            "delivered_at": 1_700_000_000,
            "delivered": True,
            "simulation_only": False,
        }
        self.events.append(event)
        return event


class MisboundNotifier(DeliveredNotifier):
    def notify(self, request: dict, gate: dict) -> dict:
        event = super().notify(request, gate)
        event["request_hash"] = "different-request"
        return event


class WrongRequestIdNotifier(DeliveredNotifier):
    def notify(self, request: dict, gate: dict) -> dict:
        event = super().notify(request, gate)
        event["request_id"] = "different-request-id"
        return event


class NonFiniteNotifier(DeliveredNotifier):
    def notify(self, request: dict, gate: dict) -> dict:
        event = super().notify(request, gate)
        event["invalid_number"] = float("nan")
        return event


class FailingNotifier:
    def notify(self, request: dict, gate: dict) -> dict:
        raise RuntimeError("notification provider failed")


class SlowApprovalVerifier(ExactApprovalVerifier):
    def verify(self, evidence: dict, request: dict) -> bool:
        time.sleep(0.05)
        return super().verify(evidence, request)


class TruthyNonBooleanVerifier:
    def verify(self, evidence: dict, request: dict):
        return "non-boolean-truthy"


class CancellingNotifier(DeliveredNotifier):
    engine: GatewayEngine | None = None

    def notify(self, request: dict, gate: dict) -> dict:
        assert self.engine is not None
        self.engine.cancel_request(request["request_id"], requester=request["requester"])
        return super().notify(request, gate)


class CancellingApprovalVerifier(ExactApprovalVerifier):
    engine: GatewayEngine | None = None

    def verify(self, evidence: dict, request: dict) -> bool:
        assert self.engine is not None
        self.engine.cancel_request(request["request_id"], requester=request["requester"])
        return True


def approval_for(request: dict, *, expires_at: int = 1_700_000_300, approval_gate_id: str | None = None, **changes) -> dict:
    gate_id = approval_gate_id or next(
        (gate["id"] for gate in request["gates"] if gate["kind"] == "approval" and gate["status"] == "waiting"),
        "approval",
    )
    evidence = {
        "trusted_test_evidence": True,
        "evidence_id": f"evidence-{request['request_id']}-{gate_id}",
        "actor": "test-human",
        "decision": "approve",
        "assurance": request.get("effective_control","step_up"),
        "request_id": request["request_id"],
        "request_hash": request["request_hash"],
        "approval_gate_id": gate_id,
        "expires_at": expires_at,
    }
    evidence.update(changes)
    return evidence


class SemanticGateEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture=json.loads((ROOT / "examples" / "calendar-booking" / "workflow.json").read_text())
        fixture["version"]=1; fixture.pop("authorization",None)
        self.policy = load_policy(fixture)
        self.clock = Clock()
        self.notifier = RecordingNotifier()
        self.registry = ToolRegistry()
        self.conditions = {"calendar_ok": True, "terms_current": True}
        self.target_calls = []
        self.registry.register_read("calendar.no_conflict", lambda args: {"ok": self.conditions["calendar_ok"], "checked": args})
        self.registry.register_read("provider.terms_current", lambda args: {"current": self.conditions["terms_current"], "checked": args})
        self.registry.register_target("calendar.create_event", lambda args: self.target_calls.append(args) or {"created": True})
        self.engine = GatewayEngine(
            self.policy,
            registry=self.registry,
            notifier=self.notifier,
            approval_verifier=ExactApprovalVerifier(),
            clock=self.clock,
        )

    def request(self, minimum_control="policy", **changes) -> dict:
        parameters = {
            "title": "Example appointment",
            "provider": "Example provider",
            "start": "2030-01-10T10:00:00Z",
            "end": "2030-01-10T10:30:00Z",
        }
        parameters.update(changes)
        return self.engine.request_action(
            action="calendar.create_event",
            parameters=parameters,
            context={"channel": "example-chat", "direct_user_request": False},
            trusted_context={"direct_user_request": True},
            requester="example-agent",
            idempotency_key="calendar-request-1",
            minimum_control=minimum_control,
        )

    def test_policy_owns_control_and_caller_floor_can_only_escalate(self):
        policy_request=self.request()
        self.assertEqual("step_up",policy_request["policy_control"])
        self.assertEqual("policy",policy_request["minimum_control"])
        self.assertEqual("step_up",policy_request["effective_control"])

        ask_floor=self.engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={},trusted_context={"direct_user_request":True},requester="example-agent",idempotency_key="ask-floor",minimum_control="ask",
        )
        self.assertEqual("step_up",ask_floor["policy_control"])
        self.assertEqual("ask",ask_floor["minimum_control"])
        self.assertEqual("step_up",ask_floor["effective_control"])

        weaker=json.loads(json.dumps(self.policy)); approval=next(g for g in weaker["workflows"]["calendar.create_event"]["gates"] if g["kind"]=="approval")
        approval["level"]="human_approve_once"; approval["ttl_seconds"]=600
        engine=GatewayEngine(load_policy(weaker),registry=self.registry,notifier=self.notifier,clock=self.clock)
        escalated=engine.request_action(
            action="calendar.create_event",parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={},trusted_context={"direct_user_request":True},requester="example-agent",idempotency_key="step-up-floor",minimum_control="step_up",
        )
        self.assertEqual("ask",escalated["policy_control"])
        self.assertEqual("step_up",escalated["effective_control"])
        self.assertEqual("human_approve_once",next(g for g in weaker["workflows"]["calendar.create_event"]["gates"] if g["kind"]=="approval")["level"])
        with self.assertRaisesRegex(ApprovalRejected,"TTL"):
            engine.ingest_trusted_approval(escalated["request_id"],approval_for(escalated,expires_at=self.clock.now+600))

    def test_minimum_control_is_bounded_and_idempotency_bound(self):
        for invalid in ("allow",None,[],{}):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(GatePolicyError,"minimum_control"):
                self.engine.request_action(action="calendar.create_event",parameters={},context={},trusted_context={},requester="example-agent",idempotency_key="bad-floor",minimum_control=invalid)
        first=self.request(minimum_control="ask")
        with self.assertRaisesRegex(GatePolicyError,"idempotency key"):
            self.engine.request_action(
                action="calendar.create_event",parameters=first["parameters"],context=first["context"],trusted_context={"direct_user_request":True},
                requester="example-agent",idempotency_key="calendar-request-1",minimum_control="step_up",
            )

    def test_policy_approval_level_is_closed_and_unknown_level_fails(self):
        malformed=json.loads(json.dumps(self.policy))
        next(g for g in malformed["workflows"]["calendar.create_event"]["gates"] if g["kind"]=="approval")["level"]="human_super_admin"
        with self.assertRaisesRegex(GatePolicyError,"approval gate"):
            load_policy(malformed)

    def test_terminal_requests_release_effective_workflow_state(self):
        request=self.request()
        self.assertIn(request["request_id"],self.engine._request_workflows)
        self.engine.cancel_request(request["request_id"],requester="example-agent")
        self.assertNotIn(request["request_id"],self.engine._request_workflows)

    def test_every_execute_path_depends_on_notification_and_approval(self):
        for action, workflow in self.policy["workflows"].items():
            with self.subTest(action=action):
                execute = next(gate for gate in workflow["gates"] if gate["kind"] == "execute")
                ancestors = set(execute["requires"])
                changed = True
                while changed:
                    changed = False
                    for gate in workflow["gates"]:
                        if gate["id"] in ancestors:
                            before = len(ancestors)
                            ancestors.update(gate["requires"])
                            changed = changed or len(ancestors) != before
                kinds = {gate["kind"] for gate in workflow["gates"] if gate["id"] in ancestors}
                self.assertIn("notify", kinds)
                self.assertIn("approval", kinds)

    def test_request_runs_preconditions_in_order_and_waits_for_human(self):
        request = self.request()
        self.assertEqual("waiting_for_approval", request["state"])
        self.assertEqual(
            ["schema", "intent", "calendar", "terms", "notify", "approval", "recheck_calendar", "recheck_terms", "execute"],
            [gate["id"] for gate in request["gates"]],
        )
        statuses = {gate["id"]: gate["status"] for gate in request["gates"]}
        self.assertEqual("passed", statuses["calendar"])
        self.assertEqual("simulated", statuses["notify"])
        self.assertEqual("waiting", statuses["approval"])
        self.assertEqual(1, len(self.notifier.events))
        self.assertFalse(self.notifier.events[0]["delivered"])
        self.assertEqual([], self.target_calls)
        self.assertFalse(request["execution_possible"])

    def test_nested_non_string_parameter_keys_are_rejected(self):
        policy = json.loads(json.dumps(self.policy))
        schema = policy["workflows"]["calendar.create_event"]["parameter_schema"]
        schema["properties"]["payload"] = {"type": "object"}
        schema["required"].append("payload")
        engine = GatewayEngine(load_policy(policy), registry=self.registry, notifier=self.notifier, clock=self.clock)
        with self.assertRaisesRegex(GatePolicyError, "JSON object keys must be strings"):
            engine.request_action(
                action="calendar.create_event",
                parameters={
                    "title":"Example", "provider":"Example", "start":"2030-01-10T10:00:00Z",
                    "end":"2030-01-10T10:30:00Z", "payload": {1: "value"},
                },
                context={}, trusted_context={}, requester="example-agent", idempotency_key="nested-key",
            )

    def test_large_json_integer_is_rejected_without_overflow(self):
        policy = load_policy(ROOT / "examples" / "purchase-approval" / "workflow.json")
        engine = GatewayEngine(policy, registry=ToolRegistry(), notifier=RecordingNotifier(), clock=self.clock)
        large_integer = 10**1000
        with self.assertRaisesRegex(GatePolicyError, "signed 64-bit range"):
            engine.request_action(
                action="purchase.place_order",
                parameters={"sku":"example","quantity":1,"unit_price":large_integer,"currency":"USD"},
                context={}, trusted_context={}, requester="example-agent", idempotency_key="large-integer",
            )

    def test_reentrant_notifier_and_verifier_cannot_mutate_their_request(self):
        notifier = CancellingNotifier()
        notifier_engine = GatewayEngine(
            self.policy, registry=self.registry, notifier=notifier,
            approval_verifier=ExactApprovalVerifier(), clock=self.clock,
        )
        notifier.engine = notifier_engine
        failed = notifier_engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="reentrant-notifier",
        )
        self.assertEqual("failed", failed["state"])
        self.assertNotEqual("waiting_for_approval", failed["state"])

        verifier = CancellingApprovalVerifier()
        verifier_engine = GatewayEngine(
            self.policy, registry=self.registry, notifier=self.notifier,
            approval_verifier=verifier, clock=self.clock,
        )
        verifier.engine = verifier_engine
        request = verifier_engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="reentrant-verifier",
        )
        with self.assertRaisesRegex(ApprovalRejected, "verifier failed"):
            verifier_engine.ingest_trusted_approval(request["request_id"], approval_for(request))
        unchanged = verifier_engine.get_request(request["request_id"])
        self.assertEqual("waiting_for_approval", unchanged["state"])
        self.assertEqual([], self.target_calls)

    def test_public_api_shape_errors_are_normalized(self):
        for operation in (
            lambda: self.engine.explain_action([]),
            lambda: self.engine.request_action(
                action=[], parameters={}, context={}, trusted_context={},
                requester="example-agent", idempotency_key="bad-action",
            ),
            lambda: self.engine.get_request([]),
            lambda: self.engine.get_request_for([], requester="example-agent"),
            lambda: self.engine.cancel_request([], requester="example-agent"),
            lambda: self.registry.call_read([], {}),
            lambda: self.registry.call_target([], {}),
        ):
            with self.assertRaises(GatePolicyError):
                operation()
        with self.assertRaises(ApprovalRejected):
            self.engine.ingest_trusted_approval([], {})

    def test_signed_64_bit_minimum_is_accepted(self):
        request = self.engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={"minimum": -(2**63)}, trusted_context={"direct_user_request":True},
            requester="example-agent", idempotency_key="signed-minimum",
        )
        self.assertEqual(-(2**63), request["context"]["minimum"])

    def test_missing_trusted_context_blocks_instead_of_erroring(self):
        request = self.engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={"direct_user_request":True}, trusted_context={},
            requester="example-agent", idempotency_key="missing-trusted-context",
        )
        self.assertEqual("blocked", request["state"])
        self.assertEqual("intent", request["blocked_by"])

    def test_context_condition_blocks_before_tool_calls(self):
        request = self.engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={"channel":"example-chat","direct_user_request":True},
            trusted_context={"direct_user_request":False},
            requester="example-agent",
            idempotency_key="no-intent",
        )
        self.assertEqual("blocked", request["state"])
        self.assertEqual("intent", request["blocked_by"])
        self.assertEqual([], self.notifier.events)

    def test_schema_and_precondition_fail_before_notification(self):
        with self.assertRaisesRegex(GatePolicyError, "unexpected parameter"):
            self.request(extra="not allowed")
        self.assertEqual([], self.notifier.events)

        self.conditions["calendar_ok"] = False
        blocked = self.request()
        self.assertEqual("blocked", blocked["state"])
        self.assertEqual("calendar", blocked["blocked_by"])
        self.assertEqual([], self.notifier.events)

    def test_unresolved_tool_input_reference_fails_terminally(self):
        policy = json.loads(json.dumps(self.policy))
        calendar_gate = next(
            gate for gate in policy["workflows"]["calendar.create_event"]["gates"]
            if gate["id"] == "calendar"
        )
        calendar_gate["input"]["start"] = "$parameters.missing"
        engine = GatewayEngine(
            load_policy(policy), registry=self.registry, notifier=self.notifier,
            approval_verifier=ExactApprovalVerifier(), clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="missing-input-reference",
        )
        self.assertEqual("failed", request["state"])
        self.assertEqual("calendar", request["blocked_by"])

    def test_read_gate_failure_is_terminal_and_not_retried(self):
        registry = ToolRegistry()
        calls = []
        def fail_read(args):
            calls.append(args)
            raise RuntimeError("read provider failed")
        registry.register_read("calendar.no_conflict", fail_read)
        registry.register_read("provider.terms_current", lambda args: {"current": True})
        engine = GatewayEngine(
            self.policy, registry=registry, notifier=self.notifier,
            approval_verifier=ExactApprovalVerifier(), clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True},
            requester="example-agent", idempotency_key="read-failure",
        )
        self.assertEqual("failed", request["state"])
        self.assertEqual("calendar", request["blocked_by"])
        self.assertEqual(1, len(calls))
        repeated = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True},
            requester="example-agent", idempotency_key="read-failure",
        )
        self.assertEqual("failed", repeated["state"])
        self.assertEqual(1, len(calls))

    def test_notifier_failure_is_terminal(self):
        engine = GatewayEngine(
            self.policy, registry=self.registry, notifier=FailingNotifier(),
            approval_verifier=ExactApprovalVerifier(), clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True},
            requester="example-agent", idempotency_key="notify-failure",
        )
        self.assertEqual("failed", request["state"])
        self.assertEqual("notify", request["blocked_by"])

    def test_truthy_non_boolean_verifier_result_is_rejected(self):
        engine = GatewayEngine(
            self.policy, registry=self.registry, notifier=self.notifier,
            approval_verifier=TruthyNonBooleanVerifier(), clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="truthy-verifier",
        )
        with self.assertRaisesRegex(ApprovalRejected, "not trusted"):
            engine.ingest_trusted_approval(request["request_id"], approval_for(request))

    def test_json_comparisons_do_not_conflate_boolean_and_number(self):
        registry = ToolRegistry()
        registry.register_read("calendar.no_conflict", lambda args: {"ok": 1})
        registry.register_read("provider.terms_current", lambda args: {"current": 1})
        engine = GatewayEngine(
            self.policy, registry=registry, notifier=self.notifier,
            approval_verifier=ExactApprovalVerifier(), clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="bool-number",
        )
        self.assertEqual("blocked", request["state"])
        self.assertEqual("calendar", request["blocked_by"])
        self.assertEqual([], self.notifier.events)

    def test_malformed_parameter_keys_raise_policy_error(self):
        with self.assertRaisesRegex(GatePolicyError, "parameter names must be strings"):
            self.engine.request_action(
                action="calendar.create_event",
                parameters={1: "bad"}, context={}, trusted_context={},
                requester="example-agent", idempotency_key="non-string-key",
            )

    def test_cancel_rejects_every_terminal_state(self):
        blocked = self.engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":False}, requester="example-agent", idempotency_key="blocked-terminal",
        )
        self.assertEqual("blocked", blocked["state"])
        with self.assertRaisesRegex(GatePolicyError, "terminal request"):
            self.engine.cancel_request(blocked["request_id"], requester="example-agent")

    def test_agent_cannot_forge_misbind_or_replay_approval(self):
        request = self.request()
        invalid = (
            approval_for(request, trusted_test_evidence=False),
            approval_for(request, request_hash="wrong"),
            approval_for(request, request_id="wrong-request"),
            approval_for(request, approval_gate_id="wrong-gate"),
            approval_for(request, evidence_id=""),
            approval_for(request, actor="another-agent"),
            approval_for(request, expires_at=self.clock.now - 1),
            approval_for(request, expires_at=self.clock.now + 301),
        )
        for evidence in invalid:
            with self.subTest(evidence=evidence):
                with self.assertRaises(ApprovalRejected):
                    self.engine.ingest_trusted_approval(request["request_id"], evidence)
        completed = self.engine.ingest_trusted_approval(request["request_id"], approval_for(request))
        self.assertEqual("simulated", completed["state"])
        with self.assertRaises(ApprovalRejected):
            self.engine.ingest_trusted_approval(request["request_id"], approval_for(request))
        self.assertEqual([], self.target_calls)

    def test_approval_evidence_cannot_replay_across_requests(self):
        first = self.request()
        second = self.engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example appointment","provider":"Example provider","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={"channel":"example-chat"}, trusted_context={"direct_user_request":True},
            requester="example-agent", idempotency_key="calendar-request-2",
        )
        self.assertNotEqual(first["request_id"], second["request_id"])
        self.assertNotEqual(first["request_hash"], second["request_hash"])
        evidence = approval_for(first)
        self.engine.ingest_trusted_approval(first["request_id"], evidence)
        with self.assertRaises(ApprovalRejected):
            self.engine.ingest_trusted_approval(second["request_id"], evidence)
        rebound = dict(
            evidence,
            request_id=second["request_id"],
            request_hash=second["request_hash"],
            approval_gate_id="approval",
        )
        with self.assertRaisesRegex(ApprovalRejected, "consumed"):
            self.engine.ingest_trusted_approval(second["request_id"], rebound)

    def test_approval_evidence_is_bound_to_one_gate(self):
        policy = json.loads(json.dumps(self.policy))
        workflow = policy["workflows"]["calendar.create_event"]
        execute = workflow["gates"].pop()
        workflow["gates"].append({
            "id": "approval_2", "kind": "approval", "requires": ["recheck_terms"],
            "level": "human_step_up", "ttl_seconds": 300,
        })
        workflow["gates"].append({
            "id": "recheck_after_approval_2", "kind": "tool", "requires": ["approval_2"],
            "tool": "calendar.no_conflict",
            "input": {"start": "$parameters.start", "end": "$parameters.end"},
            "expect": {"path": "ok", "op": "eq", "value": True},
            "recheck": True,
        })
        execute["requires"] = ["recheck_after_approval_2"]
        workflow["gates"].append(execute)
        engine = GatewayEngine(
            load_policy(policy), registry=self.registry, notifier=self.notifier,
            approval_verifier=ExactApprovalVerifier(), clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True},
            requester="example-agent", idempotency_key="two-approvals",
        )
        first_evidence = approval_for(request)
        waiting_second = engine.ingest_trusted_approval(request["request_id"], first_evidence)
        self.assertEqual("waiting_for_approval", waiting_second["state"])
        with self.assertRaises(ApprovalRejected):
            engine.ingest_trusted_approval(request["request_id"], first_evidence)
        completed = engine.ingest_trusted_approval(
            request["request_id"], approval_for(waiting_second, approval_gate_id="approval_2")
        )
        self.assertEqual("simulated", completed["state"])

    def test_exact_approval_rechecks_and_simulates_when_execution_disabled(self):
        request = self.request()
        completed = self.engine.ingest_trusted_approval(request["request_id"], approval_for(request))
        self.assertEqual("simulated", completed["state"])
        self.assertEqual("calendar.create_event", completed["would_call"]["tool"])
        self.assertFalse(completed["execution_possible"])
        self.assertEqual([], self.target_calls)

    def test_approval_expiring_during_rechecks_blocks_execute(self):
        registry = ToolRegistry()
        calendar_calls = []
        def calendar_check(args):
            calendar_calls.append(args)
            if len(calendar_calls) == 2:
                self.clock.now += 301
            return {"ok": True}
        registry.register_read("calendar.no_conflict", calendar_check)
        registry.register_read("provider.terms_current", lambda args: {"current": True})
        registry.register_target("calendar.create_event", lambda args: {"created": True})
        engine = GatewayEngine(
            self.policy, registry=registry, notifier=self.notifier,
            approval_verifier=ExactApprovalVerifier(), clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True},
            requester="example-agent", idempotency_key="expiring-during-recheck",
        )
        blocked = engine.ingest_trusted_approval(request["request_id"], approval_for(request))
        self.assertEqual("blocked", blocked["state"])
        self.assertEqual("execute", blocked["blocked_by"])
        self.assertEqual("approval_expired", blocked["gates"][-1]["evidence"]["reason"])

    def test_changed_condition_after_approval_blocks_at_recheck(self):
        request = self.request()
        self.conditions["terms_current"] = False
        blocked = self.engine.ingest_trusted_approval(request["request_id"], approval_for(request))
        self.assertEqual("blocked", blocked["state"])
        self.assertEqual("recheck_terms", blocked["blocked_by"])
        self.assertEqual([], self.target_calls)

    def test_idempotency_is_bound_to_exact_request(self):
        first = self.request()
        second = self.request()
        self.assertEqual(first["request_id"], second["request_id"])
        self.assertEqual(1, len(self.notifier.events))
        with self.assertRaisesRegex(GatePolicyError, "idempotency"):
            self.request(start="2030-01-10T11:00:00Z")

    def test_cancel_is_restrictive_and_terminal(self):
        request = self.request()
        cancelled = self.engine.cancel_request(request["request_id"], requester="example-agent")
        self.assertEqual("cancelled", cancelled["state"])
        with self.assertRaises(ApprovalRejected):
            self.engine.ingest_trusted_approval(request["request_id"], approval_for(request))

    def test_request_visibility_and_action_discovery_are_principal_scoped(self):
        request = self.request()
        self.assertNotIn("trusted_context", request)
        self.assertIn("trusted_context_hash", request)
        with self.assertRaisesRegex(GatePolicyError, "principal"):
            self.engine.get_request_for(request["request_id"], requester="other-agent")

        restricted = json.loads(json.dumps(self.policy))
        restricted["workflows"]["calendar.create_event"]["principals"] = ["allowed-agent"]
        engine = GatewayEngine(
            load_policy(restricted), registry=self.registry, notifier=self.notifier,
            approval_verifier=ExactApprovalVerifier(), clock=self.clock,
        )
        self.assertEqual([], engine.list_actions(principal="other-agent"))
        self.assertEqual(1, len(engine.list_actions(principal="allowed-agent")))
        with self.assertRaisesRegex(GatePolicyError, "principal"):
            engine.explain_action("calendar.create_event", principal="other-agent")

    def test_principal_allowlist_is_enforced_before_any_gate_runs(self):
        restricted = json.loads(json.dumps(self.policy))
        restricted["workflows"]["calendar.create_event"]["principals"] = ["allowed-agent"]
        engine = GatewayEngine(
            load_policy(restricted), registry=self.registry, notifier=self.notifier,
            approval_verifier=ExactApprovalVerifier(), clock=self.clock,
        )
        with self.assertRaisesRegex(GatePolicyError, "principal"):
            engine.request_action(
                action="calendar.create_event",
                parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
                context={"direct_user_request":False}, trusted_context={"direct_user_request":True}, requester="other-agent", idempotency_key="wrong-principal",
            )
        self.assertEqual([], self.notifier.events)

    def test_unknown_actions_fail_closed(self):
        with self.assertRaisesRegex(GatePolicyError, "not requestable"):
            self.engine.request_action(
                action="unknown.action",
                parameters={},
                context={},
                trusted_context={},
                requester="example-agent",
                idempotency_key="unknown-1",
            )

    def test_policy_rejects_invalid_parameter_and_condition_schemas_at_load(self):
        bad = json.loads(json.dumps(self.policy))
        bad["workflows"]["calendar.create_event"]["parameter_schema"]["properties"]["title"]["unknown"] = True
        with self.assertRaisesRegex(GatePolicyError, "parameter.*schema"):
            load_policy(bad)

        bad = json.loads(json.dumps(self.policy))
        bad["workflows"]["calendar.create_event"]["parameter_schema"]["required"] = [[]]
        with self.assertRaises(GatePolicyError):
            load_policy(bad)

        bad = json.loads(json.dumps(self.policy))
        bad["workflows"]["calendar.create_event"]["parameter_schema"]["properties"]["title"]["minimum"] = 0
        with self.assertRaisesRegex(GatePolicyError, "parameter.*minimum"):
            load_policy(bad)

        bad = json.loads(json.dumps(self.policy))
        condition = next(gate for gate in bad["workflows"]["calendar.create_event"]["gates"] if gate["kind"] == "condition")
        condition["path"] = 123
        with self.assertRaisesRegex(GatePolicyError, "condition"):
            load_policy(bad)

        bad = json.loads(json.dumps(self.policy))
        condition = next(gate for gate in bad["workflows"]["calendar.create_event"]["gates"] if gate["kind"] == "condition")
        condition["op"] = "in"
        condition["value"] = "not-a-list"
        with self.assertRaisesRegex(GatePolicyError, "requires a list"):
            load_policy(bad)

        bad = json.loads(json.dumps(self.policy))
        condition = next(gate for gate in bad["workflows"]["calendar.create_event"]["gates"] if gate["kind"] == "condition")
        condition["op"] = "lte"
        condition["value"] = float("nan")
        with self.assertRaises(GatePolicyError):
            load_policy(bad)

    def test_enum_comparison_does_not_conflate_boolean_and_number(self):
        policy = json.loads((ROOT / "examples" / "purchase-approval" / "workflow.json").read_text())
        policy["workflows"]["purchase.place_order"]["parameter_schema"]["properties"]["quantity"]["enum"] = [True]
        engine = GatewayEngine(load_policy(policy), registry=ToolRegistry(), notifier=RecordingNotifier(), clock=self.clock)
        with self.assertRaisesRegex(GatePolicyError, "not allowlisted"):
            engine.request_action(
                action="purchase.place_order",
                parameters={"sku":"example","quantity":1,"unit_price":1.0,"currency":"USD"},
                context={}, trusted_context={}, requester="example-agent", idempotency_key="enum-bool-number",
            )

    def test_non_finite_request_numbers_are_rejected(self):
        policy = load_policy(ROOT / "examples" / "purchase-approval" / "workflow.json")
        engine = GatewayEngine(policy, registry=ToolRegistry(), notifier=RecordingNotifier(), clock=self.clock)
        with self.assertRaisesRegex(GatePolicyError, "finite"):
            engine.request_action(
                action="purchase.place_order",
                parameters={"sku":"example","quantity":1,"unit_price":float("nan"),"currency":"USD"},
                context={}, trusted_context={}, requester="example-agent", idempotency_key="nan-price",
            )

    def test_policy_path_failures_are_normalized(self):
        with self.assertRaises(GatePolicyError):
            load_policy(ROOT / "missing-policy.json")
        with self.assertRaises(GatePolicyError):
            load_policy(ROOT)

    def test_policy_rejects_cycles_and_bypass_paths(self):
        bad = json.loads(json.dumps(self.policy))
        bad["workflows"]["calendar.create_event"]["gates"][-1]["requires"] = ["schema"]
        with self.assertRaisesRegex(GatePolicyError, "notify.*approval"):
            load_policy(bad)

        bad = json.loads(json.dumps(self.policy))
        bad["workflows"]["calendar.create_event"]["gates"][0]["requires"] = ["execute"]
        with self.assertRaisesRegex(GatePolicyError, "cycle"):
            load_policy(bad)

        bad = json.loads(json.dumps(self.policy))
        workflow = bad["workflows"]["calendar.create_event"]
        recheck = next(gate for gate in workflow["gates"] if gate["id"] == "recheck_terms")
        execute = next(gate for gate in workflow["gates"] if gate["id"] == "execute")
        recheck["requires"] = ["schema"]
        execute["requires"] = ["approval", "recheck_terms"]
        with self.assertRaisesRegex(GatePolicyError, "recheck.*approval"):
            load_policy(bad)

        bad = json.loads(json.dumps(self.policy))
        workflow = bad["workflows"]["calendar.create_event"]
        approval = next(gate for gate in workflow["gates"] if gate["id"] == "approval")
        execute = next(gate for gate in workflow["gates"] if gate["id"] == "execute")
        approval["requires"] = ["schema"]
        execute["requires"] = ["notify", "recheck_terms"]
        with self.assertRaisesRegex(GatePolicyError, "approval.*notify"):
            load_policy(bad)

        bad = json.loads(json.dumps(self.policy))
        workflow = bad["workflows"]["calendar.create_event"]
        bad["mode"] = "enforcing"
        bad["execution_enabled"] = True
        execute = next(gate for gate in workflow["gates"] if gate["kind"] == "execute")
        execute["requires"] = ["approval"]
        execute["simulation_only"] = False
        with self.assertRaisesRegex(GatePolicyError, "recheck"):
            load_policy(bad)

    def test_enforcing_mode_rejects_undelivered_notification(self):
        live_policy = json.loads(json.dumps(self.policy))
        live_policy["mode"] = "enforcing"
        live_policy["execution_enabled"] = True
        live_policy["workflows"]["calendar.create_event"]["gates"][-1]["simulation_only"] = False
        engine = GatewayEngine(
            load_policy(live_policy),
            registry=self.registry,
            notifier=RecordingNotifier(),
            approval_verifier=ExactApprovalVerifier(),
            execution_authority=ExecutionAuthority("test-host"),
            clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={"direct_user_request":False}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="undelivered",
        )
        self.assertEqual("blocked", request["state"])
        self.assertEqual("notify", request["blocked_by"])
        self.assertEqual([], self.target_calls)

    def test_enforcing_mode_rejects_misbound_notification_evidence(self):
        live_policy = json.loads(json.dumps(self.policy))
        live_policy["mode"] = "enforcing"
        live_policy["execution_enabled"] = True
        live_policy["workflows"]["calendar.create_event"]["gates"][-1]["simulation_only"] = False
        engine = GatewayEngine(
            load_policy(live_policy), registry=self.registry, notifier=MisboundNotifier(),
            approval_verifier=ExactApprovalVerifier(), execution_authority=ExecutionAuthority("test-host"), clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={"direct_user_request":False}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="misbound-notice",
        )
        self.assertEqual("blocked", request["state"])
        self.assertEqual("notify", request["blocked_by"])

    def test_enforcing_mode_rejects_wrong_notification_request_id(self):
        live_policy = json.loads(json.dumps(self.policy))
        live_policy["mode"] = "enforcing"
        live_policy["execution_enabled"] = True
        live_policy["workflows"]["calendar.create_event"]["gates"][-1]["simulation_only"] = False
        engine = GatewayEngine(
            load_policy(live_policy), registry=self.registry, notifier=WrongRequestIdNotifier(),
            approval_verifier=ExactApprovalVerifier(), execution_authority=ExecutionAuthority("test-host"), clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="wrong-notice-request",
        )
        self.assertEqual("blocked", request["state"])
        self.assertEqual("notify", request["blocked_by"])

    def test_non_finite_notifier_evidence_fails_terminally(self):
        engine = GatewayEngine(
            self.policy, registry=self.registry, notifier=NonFiniteNotifier(),
            approval_verifier=ExactApprovalVerifier(), clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="nan-notice",
        )
        self.assertEqual("failed", request["state"])
        self.assertEqual("notify", request["blocked_by"])

    def test_non_finite_adapter_results_fail_terminally(self):
        read_registry = ToolRegistry()
        read_registry.register_read("calendar.no_conflict", lambda args: {"ok": True, "bad": float("nan")})
        read_registry.register_read("provider.terms_current", lambda args: {"current": True})
        read_engine = GatewayEngine(
            self.policy, registry=read_registry, notifier=self.notifier,
            approval_verifier=ExactApprovalVerifier(), clock=self.clock,
        )
        read_failed = read_engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="nan-read",
        )
        self.assertEqual("failed", read_failed["state"])
        self.assertEqual("calendar", read_failed["blocked_by"])

        live_policy = json.loads(json.dumps(self.policy))
        live_policy["mode"] = "enforcing"
        live_policy["execution_enabled"] = True
        live_policy["workflows"]["calendar.create_event"]["gates"][-1]["simulation_only"] = False
        target_registry = ToolRegistry()
        target_registry.register_read("calendar.no_conflict", lambda args: {"ok": True})
        target_registry.register_read("provider.terms_current", lambda args: {"current": True})
        target_registry.register_target("calendar.create_event", lambda args: {"created": True, "bad": float("nan")})
        target_engine = GatewayEngine(
            load_policy(live_policy), registry=target_registry, notifier=DeliveredNotifier(),
            approval_verifier=ExactApprovalVerifier(), execution_authority=ExecutionAuthority("test-host"), clock=self.clock,
        )
        request = target_engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="nan-target",
        )
        target_failed = target_engine.ingest_trusted_approval(request["request_id"], approval_for(request))
        self.assertEqual("failed", target_failed["state"])
        self.assertEqual("execute", target_failed["gates"][-1]["id"])

    def test_target_failure_is_terminal_and_not_retried(self):
        live_policy = json.loads(json.dumps(self.policy))
        live_policy["mode"] = "enforcing"
        live_policy["execution_enabled"] = True
        live_policy["workflows"]["calendar.create_event"]["gates"][-1]["simulation_only"] = False
        registry = ToolRegistry()
        registry.register_read("calendar.no_conflict", lambda args: {"ok": True})
        registry.register_read("provider.terms_current", lambda args: {"current": True})
        calls = []
        def fail_target(args):
            calls.append(args)
            raise RuntimeError("provider failed")
        registry.register_target("calendar.create_event", fail_target)
        engine = GatewayEngine(
            load_policy(live_policy), registry=registry, notifier=DeliveredNotifier(),
            approval_verifier=ExactApprovalVerifier(), execution_authority=ExecutionAuthority("test-host"), clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={"direct_user_request":False}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="target-failure",
        )
        failed = engine.ingest_trusted_approval(request["request_id"], approval_for(request))
        self.assertEqual("failed", failed["state"])
        self.assertEqual(1, len(calls))
        with self.assertRaises(ApprovalRejected):
            engine.ingest_trusted_approval(request["request_id"], approval_for(request))
        self.assertEqual(1, len(calls))

    def test_execution_requires_host_authority_beyond_policy_configuration(self):
        live_policy = json.loads(json.dumps(self.policy))
        live_policy["mode"] = "enforcing"
        live_policy["execution_enabled"] = True
        live_policy["workflows"]["calendar.create_event"]["gates"][-1]["simulation_only"] = False
        live_policy = load_policy(live_policy)
        without_authority = GatewayEngine(
            live_policy,
            registry=self.registry,
            notifier=DeliveredNotifier(),
            approval_verifier=ExactApprovalVerifier(),
            clock=self.clock,
        )
        request = without_authority.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={"direct_user_request":False}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="no-authority",
        )
        failed = without_authority.ingest_trusted_approval(request["request_id"], approval_for(request))
        self.assertEqual("failed", failed["state"])
        self.assertEqual("MissingExecutionAuthority", failed["gates"][-1]["evidence"]["error_type"])
        with self.assertRaises(ApprovalRejected):
            without_authority.ingest_trusted_approval(request["request_id"], approval_for(request))
        self.assertEqual([], self.target_calls)

    def test_host_authority_executes_mock_target_only_after_all_gates(self):
        live_policy = json.loads(json.dumps(self.policy))
        live_policy["mode"] = "enforcing"
        live_policy["execution_enabled"] = True
        live_policy["workflows"]["calendar.create_event"]["gates"][-1]["simulation_only"] = False
        live_policy = load_policy(live_policy)
        engine = GatewayEngine(
            live_policy,
            registry=self.registry,
            notifier=DeliveredNotifier(),
            approval_verifier=ExactApprovalVerifier(),
            execution_authority=ExecutionAuthority("test-host"),
            clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={"direct_user_request":False}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="with-authority",
        )
        completed = engine.ingest_trusted_approval(request["request_id"], approval_for(request))
        self.assertEqual("executed", completed["state"])
        self.assertEqual(1, len(self.target_calls))
        self.assertTrue(completed["execution_possible"])
    def test_concurrent_approval_callbacks_execute_target_once(self):
        live_policy = json.loads(json.dumps(self.policy))
        live_policy["mode"] = "enforcing"
        live_policy["execution_enabled"] = True
        live_policy["workflows"]["calendar.create_event"]["gates"][-1]["simulation_only"] = False
        calls = []
        registry = ToolRegistry()
        registry.register_read("calendar.no_conflict", lambda args: {"ok": True})
        registry.register_read("provider.terms_current", lambda args: {"current": True})
        registry.register_target("calendar.create_event", lambda args: calls.append(args) or {"created": True})
        engine = GatewayEngine(
            load_policy(live_policy), registry=registry, notifier=DeliveredNotifier(),
            approval_verifier=SlowApprovalVerifier(), execution_authority=ExecutionAuthority("test-host"), clock=self.clock,
        )
        request = engine.request_action(
            action="calendar.create_event",
            parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
            context={}, trusted_context={"direct_user_request":True}, requester="example-agent", idempotency_key="concurrent",
        )
        outcomes = []
        def approve():
            try:
                outcomes.append(engine.ingest_trusted_approval(request["request_id"], approval_for(request))["state"])
            except Exception as error:
                outcomes.append(type(error).__name__)
        threads = [threading.Thread(target=approve) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
        self.assertEqual(1, len(calls))
        self.assertCountEqual(["executed", "ApprovalRejected"], outcomes)


if __name__ == "__main__":
    unittest.main()
