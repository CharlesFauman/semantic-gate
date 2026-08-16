#!/usr/bin/env python3
from __future__ import annotations

import unittest

from semantic_gate.catalog import build_policy
from semantic_gate.coordinator import CoreBackend
from semantic_gate.engine import ApprovalRejected


class CoreBackendTests(unittest.TestCase):
    def setUp(self):
        self.catalog = {"version":1,"actions":{
            "home.tv.power_off":{"domain":"home","risk":"R2","effect":"external_write","summary":"Turn off TV","approval":"separate_confirmation","privacy_classes":[],"constraints":[]},
            "home.read":{"domain":"home","risk":"R0","effect":"read","summary":"Read","approval":"none","privacy_classes":[],"constraints":[]},
            "system.shell.execute":{"domain":"system","risk":"R4","effect":"prohibited","summary":"Shell","approval":"prohibited","privacy_classes":[],"constraints":[]},
        }}
        self.principals = {"agent":{"role":"agent","enabled":True},"control":{"role":"admin","enabled":True}}

    def test_real_core_waits_for_host_approval_then_only_simulates(self):
        backend = CoreBackend(build_policy(self.catalog, self.principals), approval_key=bytes.fromhex("22" * 32), clock=lambda: 100)
        request = backend.request_action(
            action="home.tv.power_off",
            parameters={"summary":"Turn TV off","target":"living-room-tv","details":{}},
            context={"surface":"test"}, trusted_context={"surface":"test"},
            requester="agent", idempotency_key="core-one",
        )
        self.assertEqual("waiting_for_approval", request["state"])
        self.assertFalse(request["execution_possible"])
        approved = backend.approve_request(request["request_id"], actor="control")
        self.assertEqual("simulated", approved["state"])
        self.assertFalse(approved["execution_possible"])
        self.assertEqual("semantic.action.home.tv.power_off", approved["would_call"]["tool"])

    def test_step_up_requires_step_up_assurance(self):
        backend=CoreBackend(build_policy(self.catalog,self.principals),approval_key=bytes.fromhex("22"*32),clock=lambda:100)
        request=backend.request_action(action="home.tv.power_off",parameters={"summary":"Turn TV off","target":"living-room-tv","details":{}},context={},trusted_context={},requester="agent",idempotency_key="step",minimum_control="step_up")
        with self.assertRaisesRegex(ApprovalRejected,"assurance"):
            backend.approve_request(request["request_id"],actor="control",assurance="ask")
        approved=backend.approve_request(request["request_id"],actor="signed-human",assurance="step_up")
        self.assertEqual("simulated",approved["state"])

    def test_read_and_prohibited_catalog_entries_are_not_requestable(self):
        backend = CoreBackend(build_policy(self.catalog, self.principals), approval_key=bytes.fromhex("22" * 32), clock=lambda: 100)
        for action in ("home.read", "system.shell.execute"):
            with self.subTest(action=action), self.assertRaises(Exception):
                backend.request_action(action=action, parameters={}, context={}, trusted_context={}, requester="agent", idempotency_key=action)


if __name__ == "__main__":
    unittest.main()
