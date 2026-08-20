#!/usr/bin/env python3
from __future__ import annotations

import unittest

from semantic_gate.catalog import (
    GATE_CLASSES,
    HUMAN_GATE_CLASSES,
    action_gate_class,
    build_policy,
    validate_catalog,
)


class PolicyBuilderTests(unittest.TestCase):
    def setUp(self):
        self.catalog = {
            "version": 1,
            "actions": {
                "home.tv.power_off": {"domain": "home", "risk": "R2", "effect": "external_write", "summary": "Turn off TV", "approval": "separate_confirmation", "gate_class": "automatic", "privacy_classes": [], "constraints": []},
                "purchase.place_order": {"domain": "purchase", "risk": "R3", "effect": "external_write", "summary": "Buy item", "approval": "step_up", "gate_class": "human_spending", "privacy_classes": ["financial"], "constraints": []},
                "communication.send_email": {"domain": "communication", "risk": "R3", "effect": "external_write", "summary": "Email a person", "approval": "separate_confirmation", "gate_class": "human_communication", "privacy_classes": [], "constraints": []},
                "system.shell.execute": {"domain": "system", "risk": "R4", "effect": "prohibited", "summary": "Shell", "approval": "prohibited", "gate_class": "prohibited", "privacy_classes": [], "constraints": []},
                "home.read": {"domain": "home", "risk": "R0", "effect": "read", "summary": "Read", "approval": "none", "gate_class": "automatic", "privacy_classes": [], "constraints": []},
                "finance.balance.read": {"domain": "finance", "risk": "R1", "effect": "read", "summary": "Read account balance", "approval": "none", "gate_class": "automatic", "privacy_classes": ["financial"], "constraints": []},
                "deploy.internal.release": {"domain": "deploy", "risk": "R2", "effect": "external_write", "summary": "Deploy to the internal staging cluster", "approval": "separate_confirmation", "gate_class": "automatic", "privacy_classes": [], "constraints": []},
            },
        }
        self.principals = {"hermes-mac": {"role": "agent", "enabled": True}, "audit-only": {"role": "observer", "enabled": True}, "codex": {"role": "agent", "enabled": False}, "control-panel": {"role": "admin", "enabled": True}}

    # --- the classification vocabulary is closed and exhaustive ------------------------
    def test_gate_class_enum_is_exactly_the_closed_four_way_vocabulary(self):
        self.assertEqual(("automatic", "human_communication", "human_spending", "prohibited"), GATE_CLASSES)
        self.assertEqual(("human_communication", "human_spending"), HUMAN_GATE_CLASSES)
        self.assertEqual("automatic", action_gate_class(self.catalog["actions"]["home.read"]))
        self.assertEqual("human_spending", action_gate_class(self.catalog["actions"]["purchase.place_order"]))
        self.assertIsNone(action_gate_class({"risk": "R1"}))
        self.assertIsNone(action_gate_class({"gate_class": "everything"}))
        self.assertIsNone(action_gate_class({"gate_class": ["automatic"]}))
        self.assertIsNone(action_gate_class("not-a-mapping"))

    def test_every_catalogue_entry_must_declare_exactly_one_consistent_class(self):
        for label, broken in (
            ("missing", {"risk": "R1", "effect": "read", "approval": "none"}),
            ("unknown", {"risk": "R1", "effect": "read", "approval": "none", "gate_class": "everything"}),
            ("not-a-string", {"risk": "R1", "effect": "read", "approval": "none", "gate_class": ["automatic"]}),
            ("effect-conflict", {"risk": "R4", "effect": "prohibited", "approval": "separate_confirmation", "gate_class": "automatic"}),
            ("approval-conflict", {"risk": "R4", "effect": "external_write", "approval": "prohibited", "gate_class": "human_spending"}),
            ("prohibited-without-marker", {"risk": "R1", "effect": "read", "approval": "none", "gate_class": "prohibited"}),
        ):
            with self.subTest(label=label):
                catalog = {"version": 1, "actions": {**self.catalog["actions"], "broken.action": broken}}
                with self.assertRaises(ValueError):
                    validate_catalog(catalog)
                with self.assertRaises(ValueError):
                    build_policy(catalog, self.principals)
        for malformed in (None, [], {"actions": None}, {"actions": {"x": None}}, {"actions": {7: {"gate_class": "automatic"}}}):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ValueError):
                    validate_catalog(malformed)
        self.assertEqual(self.catalog, validate_catalog(self.catalog))

    # --- every non-prohibited action gets a workflow; prohibited stays unrequestable ---
    def test_generates_workflows_for_every_non_prohibited_action_including_reads(self):
        policy = build_policy(self.catalog, self.principals)
        self.assertEqual("simulation_only", policy["mode"])
        self.assertFalse(policy["execution_enabled"])
        self.assertEqual(set(self.catalog["actions"]) - {"system.shell.execute"}, set(policy["workflows"]))
        for action in ("home.read", "finance.balance.read", "deploy.internal.release", "communication.send_email"):
            with self.subTest(action=action):
                workflow = policy["workflows"][action]
                self.assertEqual(["control-panel", "hermes-mac"], workflow["principals"])
                self.assertNotIn("*", workflow["principals"])
                self.assertEqual(["schema", "tool", "notify", "approval", "tool", "execute"], [gate["kind"] for gate in workflow["gates"]])
                self.assertTrue(workflow["gates"][-1]["simulation_only"])

    def test_prohibited_actions_never_receive_a_workflow(self):
        policy = build_policy(self.catalog, self.principals)
        self.assertNotIn("system.shell.execute", policy["workflows"])

    def test_sensitive_action_has_shorter_step_up_ttl(self):
        policy = build_policy(self.catalog, self.principals)
        approval = next(g for g in policy["workflows"]["purchase.place_order"]["gates"] if g["kind"] == "approval")
        self.assertEqual("human_step_up", approval["level"])
        self.assertEqual(300, approval["ttl_seconds"])


if __name__ == "__main__":
    unittest.main()
