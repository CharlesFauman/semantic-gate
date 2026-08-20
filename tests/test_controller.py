#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from semantic_gate.controller import GateControl, GateControlError, GateDecisionConflict
from semantic_gate.projection import collapse_observations
from semantic_gate.storage import Ledger


class AutoApprovingBackend:
    """Backend fake exposing the policy-owned auto-approval contract."""

    def __init__(self, matched=True):
        self.matched = matched
        self.requests = {}
        self.seen = []

    def request_action(self, *, action, parameters, context, trusted_context, requester, idempotency_key, minimum_control="policy"):
        request = {"request_id": "req_auto", "request_hash": "a" * 64, "action": action, "requester": requester,
                   "state": "waiting_for_approval", "created_at": 100, "parameters": parameters, "context": context,
                   "minimum_control": minimum_control, "policy_control": "ask", "effective_control": "ask",
                   "gates": [{"id": "approval", "kind": "approval", "status": "waiting", "evidence": {"ttl_seconds": 300}}]}
        request["approval_challenge"] = {"request_id": "req_auto", "request_hash": "a" * 64,
                                         "approval_gate_id": "approval", "expires_at": 400}
        self.requests["req_auto"] = request
        return dict(request)

    def approval_challenge(self, request_id):
        return dict(self.requests[request_id]["approval_challenge"])

    def get_request(self, request_id, requester=None):
        return dict(self.requests[request_id])

    def auto_approval_decision(self, request, *, paused=False, disabled_rules=()):
        self.seen.append((paused, tuple(disabled_rules)))
        if not self.matched:
            return {"matched": False, "reason_code": "spending_requires_human",
                    "reason": "Spending, transferring, purchasing or committing money always requires a human decision. (class: human_spending)"}
        return {"matched": True, "reason_code": "matched_global_simulation_scope",
                "reason": "Matched the standing simulation-only rule; nothing is executed.",
                "rule_id": "rule-global-simulation", "rule_version": 1,
                "evidence_binding": {"rule_id": "rule-global-simulation"}}

    def auto_approve(self, request_id, decision):
        self.requests[request_id]["state"] = "simulated"
        audit = {"auto_approved": True, "rule_id": "rule-global-simulation", "rule_version": 1,
                 "policy_version": 7, "request_id": request_id, "request_hash": "a" * 64,
                 "commit": None, "action_class": "global_simulation",
                 "reason_code": "matched_global_simulation_scope", "authorizes_execution": False}
        return dict(self.requests[request_id]), {"evidence_id": "auto_1", "authorizes_execution": False}, audit


class FakeBackend:
    def __init__(self):
        self.calls = []
        self.requests = {}

    def list_actions(self, principal):
        return [{"action":"home.tv.power_off"},{"action":"purchase.place_order"}]

    def explain_action(self, action, principal):
        return {"action":action,"execution_enabled":False}

    def request_action(self, *, action, parameters, context, trusted_context, requester, idempotency_key, minimum_control="policy"):
        self.calls.append((action, requester, trusted_context, minimum_control))
        request = {"request_id":f"req_{len(self.calls)}","request_hash":"h"*64,"action":action,"requester":requester,"state":"waiting_for_approval","created_at":100,"parameters":parameters,"context":context,"minimum_control":minimum_control,"gates":[{"id":"approve","kind":"approval","status":"waiting","evidence":{"ttl_seconds":300}}]}
        request["approval_challenge"]={"request_id":request["request_id"],"request_hash":request["request_hash"],"approval_gate_id":"approve","expires_at":400}
        self.requests[request["request_id"]] = request
        return dict(request)

    def approval_challenge(self, request_id):
        return dict(self.requests[request_id]["approval_challenge"])

    def get_request(self, request_id, requester=None):
        return dict(self.requests[request_id])

    def cancel_request(self, request_id, requester):
        self.requests[request_id]["state"] = "cancelled"
        return dict(self.requests[request_id])

    def approve_request(self, request_id, actor, challenge):
        self.requests[request_id]["state"] = "simulated"
        return dict(self.requests[request_id])

    def deny_request(self, request_id, actor, challenge):
        self.requests[request_id]["state"] = "denied"
        return dict(self.requests[request_id])


class GateControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = Ledger(Path(self.tmp.name) / "ledger.sqlite3")
        self.backend = FakeBackend()
        self.control = GateControl(self.backend, self.ledger, clock=lambda: 100)

    def tearDown(self):
        self.ledger.close()
        self.tmp.cleanup()

    def test_authenticated_principal_and_host_context_cannot_be_overridden(self):
        result = self.control.request_action(
            principal="hermes-mac",
            payload={"action":"home.tv.power_off","parameters":{"target":"living-room"},"context":{"requester":"forged"},"idempotency_key":"one"},
            host_context={"direct_user_request":False,"surface":"mcp"},
        )
        self.assertEqual("hermes-mac", result["requester"])
        self.assertEqual(("home.tv.power_off", "hermes-mac", {"direct_user_request":False,"surface":"mcp"}, "policy"), self.backend.calls[0])
        self.assertNotIn("trusted_context", result)
        self.assertEqual("waiting_for_approval", self.ledger.get_request(result["request_id"])["state"])
        for forbidden in ("requester", "trusted_context", "mode", "approval", "required_control"):
            payload = {"action":"home.tv.power_off","parameters":{},"context":{},"idempotency_key":forbidden,forbidden:"forged"}
            with self.subTest(forbidden=forbidden), self.assertRaisesRegex(GateControlError, "unknown request field"):
                self.control.request_action(principal="hermes-mac", payload=payload, host_context={})

    def test_caller_can_only_supply_bounded_minimum_control_floor(self):
        result=self.control.request_action(principal="hermes-mac",payload={"action":"home.tv.power_off","parameters":{},"context":{},"idempotency_key":"floor","minimum_control":"step_up"},host_context={})
        self.assertEqual("step_up",result["minimum_control"])
        self.assertEqual("step_up",self.backend.calls[-1][-1])
        for invalid in ("allow",None,[],{}):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(GateControlError,"minimum_control"):
                self.control.request_action(principal="hermes-mac",payload={"action":"home.tv.power_off","parameters":{},"context":{},"idempotency_key":"bad","minimum_control":invalid},host_context={})

    def test_pause_domain_and_revoke_fail_before_backend(self):
        self.control.set_control("paused_domains", ["purchase"], actor="control-panel")
        self.control.set_control("revoked_principals", ["codex"], actor="control-panel")
        with self.assertRaisesRegex(GateControlError, "paused"):
            self.control.request_action(principal="hermes-mac", payload={"action":"purchase.place_order","parameters":{},"context":{},"idempotency_key":"p"}, host_context={})
        with self.assertRaisesRegex(GateControlError, "revoked"):
            self.control.request_action(principal="codex", payload={"action":"home.tv.power_off","parameters":{},"context":{},"idempotency_key":"c"}, host_context={})
        self.assertEqual([], self.backend.calls)

    def test_only_admin_transport_can_approve_and_simulation_stays_non_effectful(self):
        request = self.control.request_action(principal="hermes-mac", payload={"action":"home.tv.power_off","parameters":{},"context":{},"idempotency_key":"a"}, host_context={})
        with self.assertRaisesRegex(GateControlError, "admin"):
            self.control.approve(request["request_id"], actor="hermes-mac", actor_role="agent", challenge=request["approval_challenge"])
        result = self.control.approve(request["request_id"], actor="control-panel", actor_role="admin", challenge=request["approval_challenge"])
        self.assertEqual("simulated", result["state"])
        self.assertFalse(result.get("execution_possible", False))
        self.assertEqual(["requested", "approved"], [event["event"] for event in self.ledger.audit_events(request["request_id"])])
        approved_event=self.ledger.audit_events(request["request_id"])[-1]
        self.assertEqual({**request["approval_challenge"],"decision":"approve"},approved_event["metadata"])

    def test_decisions_require_the_exact_unexpired_challenge_and_are_single_use(self):
        request=self.control.request_action(principal="hermes-mac",payload={"action":"home.tv.power_off","parameters":{},"context":{},"idempotency_key":"challenge"},host_context={})
        exact=request["approval_challenge"]
        for challenge in ({},{**exact,"request_hash":"0"*64},{**exact,"approval_gate_id":"other"},{**exact,"expires_at":401}):
            with self.subTest(challenge=challenge),self.assertRaises(GateDecisionConflict):
                self.control.deny(request["request_id"],actor="control-panel",actor_role="admin",challenge=challenge)
        denied=self.control.deny(request["request_id"],actor="control-panel",actor_role="admin",challenge=exact)
        self.assertEqual("denied",denied["state"])
        self.assertEqual({**exact,"decision":"deny"},self.ledger.audit_events(request["request_id"])[-1]["metadata"])
        before=self.ledger.audit_events(request["request_id"])
        with self.assertRaises(GateDecisionConflict):
            self.control.approve(request["request_id"],actor="control-panel",actor_role="admin",challenge=exact)
        self.assertEqual(before,self.ledger.audit_events(request["request_id"]))

    def test_persisted_terminal_request_remains_readable_after_backend_restart(self):
        request={"request_id":"old","request_hash":"h","action":"home.tv.power_off","requester":"hermes-mac","state":"expired","created_at":1,"updated_at":2,"parameters":{},"context":{},"gates":[]}
        self.ledger.record_request(request,event="expired_on_restart",actor="system")
        result=self.control.get_request("old",principal="hermes-mac")
        self.assertEqual("expired",result["state"])

    def test_observation_identity_and_privacy_shape_are_host_enforced(self):
        payload={"event_id":"call-1:completed","phase":"completed","operation":"terminal","semantic_class":"compute.exec.arbitrary","outcome":"succeeded","occurred_at":99,"metadata":{"surface":"hermes","duration_ms":12}}
        result=self.control.observe(principal="hermes-mac",payload=payload)
        self.assertEqual("hermes-mac",result["principal"])
        self.assertEqual(100,result["received_at"])
        self.control.clock=lambda:101
        self.assertEqual(result,self.control.observe(principal="hermes-mac",payload=payload))
        with self.assertRaisesRegex(GateControlError,"unknown observation field"):
            self.control.observe(principal="hermes-mac",payload={**payload,"principal":"forged"})
        with self.assertRaisesRegex(GateControlError,"metadata key"):
            self.control.observe(principal="hermes-mac",payload={**payload,"event_id":"call-2","metadata":{"raw_args":{"secret":"no"}}})
        with self.assertRaisesRegex(GateControlError,"flat scalar"):
            self.control.observe(principal="hermes-mac",payload={**payload,"event_id":"call-2b","metadata":{"surface":{"secret":"no"}}})
        with self.assertRaisesRegex(GateControlError,"metadata key"):
            self.control.observe(principal="hermes-mac",payload={**payload,"event_id":"call-3","metadata":{"raw":"rm -rf /"}})
        with self.assertRaisesRegex(GateControlError,"operation is invalid"):
            self.control.observe(principal="hermes-mac",payload={**payload,"event_id":"call-4","operation":"rm -rf /"})


class AutoApprovalOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = Ledger(Path(self.tmp.name) / "ledger.sqlite3")

    def tearDown(self):
        self.ledger.close(); self.tmp.cleanup()

    def control_for(self, backend):
        return GateControl(backend, self.ledger, clock=lambda: 100)

    def propose(self, control, action="code.edit_file"):
        return control.request_action(principal="agent-code-1", host_context={"surface": "http", "node": "node-example-1"},
                                      payload={"action": action, "parameters": {"summary": "Simulate"}, "context": {},
                                               "idempotency_key": "auto-one"})

    def test_matched_requests_are_auto_approved_and_immutably_audited(self):
        backend = AutoApprovingBackend()
        request = self.propose(self.control_for(backend))
        self.assertEqual("simulated", request["state"])
        self.assertTrue(request["auto_approval"]["matched"])
        self.assertEqual("rule-global-simulation", request["auto_approval"]["rule_id"])
        self.assertIs(False, request["auto_approval"]["authorizes_execution"])
        events = self.ledger.audit_events()
        self.assertEqual(["requested", "auto_approved"], [event["event"] for event in events])
        self.assertEqual("a" * 64, events[-1]["metadata"]["request_hash"])
        self.assertEqual(1, events[-1]["metadata"]["rule_version"])
        self.assertIs(False, events[-1]["metadata"]["authorizes_execution"])
        self.assertEqual("simulated", self.ledger.get_request("req_auto")["state"])

    def test_unmatched_requests_keep_the_human_gate_with_a_safe_dry_run_reason(self):
        backend = AutoApprovingBackend(matched=False)
        request = self.propose(self.control_for(backend))
        self.assertEqual("waiting_for_approval", request["state"])
        self.assertFalse(request["auto_approval"]["matched"])
        self.assertEqual("spending_requires_human", request["auto_approval"]["reason_code"])
        self.assertIn("human_spending", request["auto_approval"]["reason"])
        self.assertEqual(["requested"], [event["event"] for event in self.ledger.audit_events()])

    def test_human_pause_and_rule_disable_controls_reach_the_matcher(self):
        backend = AutoApprovingBackend()
        control = self.control_for(backend)
        self.ledger.set_control("auto_approval_paused", True, actor="control", now=100)
        self.ledger.set_control("disabled_auto_rules", ["rule-global-simulation"], actor="control", now=100)
        self.propose(control)
        self.assertEqual((True, ("rule-global-simulation",)), backend.seen[-1])
        self.assertIs(True, self.ledger.controls()["auto_approval_paused"])
        self.assertEqual(["rule-global-simulation"], self.ledger.controls()["disabled_auto_rules"])

    def test_correlated_root_and_detail_observations_are_stored_and_collapse_to_one_row(self):
        control = self.control_for(AutoApprovingBackend())
        payload = {"event_id": "call-1", "correlation_id": "corr-1", "phase": "completed",
                   "operation": "code.edit_file", "semantic_class": "code.change.write", "outcome": "failed",
                   "occurred_at": 99, "metadata": {"surface": "harness", "error_type": "nonzero_exit"}}
        control.observe(principal="agent-code-1", payload=payload)
        control.observe(principal="agent-code-1", payload={**payload, "event_id": "call-1-detail", "occurred_at": 100})
        rows = self.ledger.recent_observations(limit=10)
        self.assertEqual(2, len(rows))
        self.assertEqual({"corr-1"}, {row["correlation_id"] for row in rows})
        collapsed = collapse_observations(rows)
        self.assertEqual(1, len(collapsed))
        self.assertEqual(2, collapsed[0]["occurrences"])
        self.assertFalse(collapsed[0]["is_gate_failure"])
        with self.assertRaisesRegex(GateControlError, "correlation_id"):
            control.observe(principal="agent-code-1", payload={**payload, "event_id": "call-2", "correlation_id": "bad id!"})
        control.observe(principal="agent-code-1", payload={key: value for key, value in payload.items() if key != "correlation_id"} | {"event_id": "call-3"})
        self.assertIsNone(collapse_observations(self.ledger.recent_observations(limit=10))[-1]["correlation_id"])


if __name__ == "__main__":
    unittest.main()
