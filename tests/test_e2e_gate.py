#!/usr/bin/env python3
"""End-to-end tests over the real CoreBackend + GateControl + Ledger wiring.

The final policy under test: every catalogued non-prohibited proposal is
auto-approved for simulation EXCEPT catalogue entries classified
human_communication or human_spending, which always await a human decision.
Prohibited entries are unrequestable, and execution stays disabled throughout.
"""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from semantic_gate.autoapproval import AutoApprovalPolicy
from semantic_gate.catalog import build_policy
from semantic_gate.controller import GateControl
from semantic_gate.coordinator import CoreBackend
from semantic_gate.engine import GatePolicyError
from semantic_gate.storage import Ledger

CATALOG = {"version": 1, "actions": {
    "code.edit_file": {"domain": "code", "risk": "R1", "effect": "write", "summary": "Apply one reviewed patch", "approval": "separate_confirmation", "gate_class": "automatic"},
    "deploy.internal.release": {"domain": "deploy", "risk": "R2", "effect": "external_write", "summary": "Deploy to the internal staging cluster", "approval": "separate_confirmation", "gate_class": "automatic"},
    "finance.balance.read": {"domain": "finance", "risk": "R1", "effect": "read", "summary": "Read the account balance", "approval": "none", "gate_class": "automatic"},
    "communication.send_email": {"domain": "communication", "risk": "R2", "effect": "external_write", "summary": "Send one email to a person", "approval": "separate_confirmation", "gate_class": "human_communication"},
    "payments.transfer": {"domain": "payments", "risk": "R2", "effect": "external_write", "summary": "Transfer money", "approval": "separate_confirmation", "gate_class": "human_spending"},
    "system.shell.execute": {"domain": "system", "risk": "R4", "effect": "prohibited", "summary": "Shell", "approval": "prohibited", "gate_class": "prohibited"},
}}
PRINCIPALS = {"agent": {"role": "agent", "enabled": True}, "control": {"role": "admin", "enabled": True}}
STANDING_DOCUMENT = {"version": 5, "enabled": True, "rules": [], "global_simulation_rule": {
    "rule_id": "rule-global-simulation", "version": 1,
    "human_gate_classes": ["human_communication", "human_spending"],
    "requesters": ["agent"], "nodes": ["node-example-1"],
    "expires_at": 86_500, "review_by": 3_700}}


class DeliveredNotifier:
    def notify(self, request, gate):
        return {"delivered": True, "notification_id": "notice_" + request["request_hash"][:16],
                "request_id": request["request_id"], "request_hash": request["request_hash"],
                "notification_gate_id": gate["id"], "recipient": gate["recipient"],
                "template_hash": hashlib.sha256(gate["template"].encode()).hexdigest(), "delivered_at": 100}


class EndToEndGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = Ledger(Path(self.tmp.name) / "ledger.sqlite3")

    def tearDown(self):
        self.ledger.close()
        self.tmp.cleanup()

    def wire(self, policy=None):
        backend = CoreBackend(
            policy if policy is not None else build_policy(CATALOG, PRINCIPALS),
            approval_key=bytes.fromhex("22" * 32), clock=lambda: 100,
            notifier=DeliveredNotifier(), auto_approval=AutoApprovalPolicy(STANDING_DOCUMENT), catalog=CATALOG,
        )
        return backend, GateControl(backend, self.ledger, clock=lambda: 100)

    def propose(self, control, action, key):
        return control.request_action(
            principal="agent",
            payload={"action": action, "parameters": {"summary": "Reviewed proposal", "target": "example-target", "details": {}},
                     "context": {}, "idempotency_key": key},
            host_context={"surface": "http", "authenticated_principal": "agent", "node": "node-example-1"},
        )

    def test_automatic_action_traverses_every_gate_and_only_simulates(self):
        backend, control = self.wire()
        request = self.propose(control, "code.edit_file", "e2e-auto")
        self.assertEqual("simulated", request["state"])
        gates = {gate["id"]: gate for gate in request["gates"]}
        self.assertEqual("passed", gates["schema"]["status"])
        self.assertEqual("passed", gates["precheck"]["status"])
        self.assertEqual("approved", gates["approval"]["status"])
        self.assertEqual("passed", gates["recheck"]["status"])
        self.assertEqual("simulated", gates["execute"]["status"])
        evidence = gates["approval"]["evidence"]
        self.assertTrue(evidence["evidence_id"].startswith("auto_"))
        self.assertEqual(request["request_hash"], evidence["request_hash"])
        self.assertEqual(request["request_id"], evidence["request_id"])
        self.assertEqual("policy:auto-approval:rule-global-simulation", evidence["actor"])
        self.assertIs(False, request["execution_possible"])
        self.assertEqual("semantic.action.code.edit_file", request["would_call"]["tool"])
        self.assertEqual({"matched": True, "reason_code": "matched_global_simulation_scope",
                          "rule_id": "rule-global-simulation", "rule_version": 1, "authorizes_execution": False},
                         {key: request["auto_approval"][key] for key in
                          ("matched", "reason_code", "rule_id", "rule_version", "authorizes_execution")})
        events = self.ledger.audit_events(request["request_id"])
        self.assertEqual(["requested", "auto_approved"], [event["event"] for event in events])
        self.assertIs(False, events[-1]["metadata"]["authorizes_execution"])
        self.assertIsNone(backend.approval_challenge(request["request_id"]))

    def test_internal_deploy_and_balance_read_are_auto_approved_end_to_end(self):
        _backend, control = self.wire()
        for action in ("deploy.internal.release", "finance.balance.read"):
            with self.subTest(action=action):
                request = self.propose(control, action, f"e2e-{action}")
                self.assertEqual("simulated", request["state"])
                self.assertTrue(request["auto_approval"]["matched"])
                self.assertIs(False, request["execution_possible"])

    def test_communication_and_spending_await_a_human_decision(self):
        _backend, control = self.wire()
        email = self.propose(control, "communication.send_email", "e2e-email")
        self.assertEqual("waiting_for_approval", email["state"])
        self.assertFalse(email["auto_approval"]["matched"])
        self.assertEqual("communication_requires_human", email["auto_approval"]["reason_code"])
        transfer = self.propose(control, "payments.transfer", "e2e-transfer")
        self.assertEqual("waiting_for_approval", transfer["state"])
        self.assertEqual("spending_requires_human", transfer["auto_approval"]["reason_code"])
        self.assertEqual(["requested"], [event["event"] for event in self.ledger.audit_events(email["request_id"])])
        approved = control.approve(email["request_id"], actor="control", actor_role="admin", challenge=email["approval_challenge"])
        self.assertEqual("simulated", approved["state"])
        self.assertFalse(approved.get("execution_possible", False))
        denied = control.deny(transfer["request_id"], actor="control", actor_role="admin", challenge=transfer["approval_challenge"])
        self.assertEqual("denied", denied["state"])

    def test_prohibited_actions_stay_closed_end_to_end(self):
        _backend, control = self.wire()
        actions = [item["action"] for item in control.list_actions("agent")]
        self.assertNotIn("system.shell.execute", actions)
        with self.assertRaisesRegex(GatePolicyError, "not requestable"):
            self.propose(control, "system.shell.execute", "e2e-shell")
        self.assertEqual([], self.ledger.audit_events())

    def test_execution_enabled_policy_blocks_the_standing_simulation_approval(self):
        enforcing = {**build_policy(CATALOG, PRINCIPALS), "mode": "enforcing", "execution_enabled": True}
        backend, control = self.wire(policy=enforcing)
        self.assertIs(True, backend.execution_enabled)
        request = self.propose(control, "code.edit_file", "e2e-enforcing")
        self.assertEqual("waiting_for_approval", request["state"])
        self.assertFalse(request["auto_approval"]["matched"])
        self.assertEqual("global_rule_requires_simulation_only", request["auto_approval"]["reason_code"])
        self.assertEqual(["requested"], [event["event"] for event in self.ledger.audit_events(request["request_id"])])


if __name__ == "__main__":
    unittest.main()
