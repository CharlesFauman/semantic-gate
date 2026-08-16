#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from semantic_gate.catalog import build_policy


class PolicyBuilderTests(unittest.TestCase):
    def setUp(self):
        self.catalog = {
            "version":1,
            "actions": {
                "home.tv.power_off":{"domain":"home","risk":"R2","effect":"external_write","summary":"Turn off TV","approval":"separate_confirmation","privacy_classes":[],"constraints":[]},
                "purchase.place_order":{"domain":"purchase","risk":"R3","effect":"external_write","summary":"Buy item","approval":"step_up","privacy_classes":["financial"],"constraints":[]},
                "system.shell.execute":{"domain":"system","risk":"R4","effect":"prohibited","summary":"Shell","approval":"prohibited","privacy_classes":[],"constraints":[]},
                "home.read":{"domain":"home","risk":"R0","effect":"read","summary":"Read","approval":"none","privacy_classes":[],"constraints":[]},
            },
        }
        self.principals = {"hermes-mac":{"role":"agent","enabled":True},"audit-only":{"role":"observer","enabled":True},"codex":{"role":"agent","enabled":False},"control-panel":{"role":"admin","enabled":True}}

    def test_generates_only_mutating_requestable_actions_with_explicit_principals(self):
        policy = build_policy(self.catalog, self.principals)
        self.assertEqual("simulation_only", policy["mode"])
        self.assertFalse(policy["execution_enabled"])
        self.assertEqual({"home.tv.power_off","purchase.place_order"}, set(policy["workflows"]))
        workflow = policy["workflows"]["home.tv.power_off"]
        self.assertEqual(["control-panel","hermes-mac"], workflow["principals"])
        self.assertNotIn("*", workflow["principals"])
        self.assertEqual(["schema","tool","notify","approval","tool","execute"], [gate["kind"] for gate in workflow["gates"]])
        self.assertTrue(workflow["gates"][-1]["simulation_only"])

    def test_sensitive_action_has_shorter_step_up_ttl(self):
        policy = build_policy(self.catalog, self.principals)
        approval = next(g for g in policy["workflows"]["purchase.place_order"]["gates"] if g["kind"] == "approval")
        self.assertEqual("human_step_up", approval["level"])
        self.assertEqual(300, approval["ttl_seconds"])


if __name__ == "__main__":
    unittest.main()
