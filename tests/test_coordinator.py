#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from semantic_gate.authorization import SQLiteAuthorizationStore
from semantic_gate.catalog import build_policy
from semantic_gate.coordinator import CoreBackend
from semantic_gate.engine import ApprovalRejected
from semantic_gate.storage import Ledger


class CoreBackendTests(unittest.TestCase):
    def setUp(self):
        self.catalog = {"version":1,"actions":{
            "home.tv.power_off":{"domain":"home","risk":"R2","effect":"external_write","summary":"Turn off TV","approval":"separate_confirmation","privacy_classes":[],"constraints":[]},
            "home.read":{"domain":"home","risk":"R0","effect":"read","summary":"Read","approval":"none","privacy_classes":[],"constraints":[]},
            "system.shell.execute":{"domain":"system","risk":"R4","effect":"prohibited","summary":"Shell","approval":"prohibited","privacy_classes":[],"constraints":[]},
        }}
        self.principals = {"agent":{"role":"agent","enabled":True},"control":{"role":"admin","enabled":True}}
        self.tmp=tempfile.TemporaryDirectory(); self.store=SQLiteAuthorizationStore(Path(self.tmp.name)/"auth.sqlite3")

    def tearDown(self): self.store.close(); self.tmp.cleanup()

    def backend(self):
        return CoreBackend(build_policy(self.catalog,self.principals),approval_key=bytes.fromhex("22"*32),authorization_key=bytes.fromhex("33"*32),authorization_store=self.store,clock=lambda:100)

    def test_real_core_waits_for_host_approval_then_issues_authorization(self):
        backend = self.backend()
        request = backend.request_action(
            action="home.tv.power_off",
            parameters={"summary":"Turn TV off","target":"living-room-tv","details":{}},
            context={"surface":"test"}, trusted_context={"surface":"test"},
            requester="agent", idempotency_key="core-one",
        )
        self.assertEqual("waiting_for_approval", request["state"])
        self.assertFalse(request["execution_possible"])
        ledger=Ledger(self.store.path); persisted=dict(request); persisted["updated_at"]=100; ledger.record_request(persisted,event="requested",actor="agent")
        provenance={"transport":"ed25519","key_id":"owner-key","signed_at":99,"signature_sha256":"a"*64}
        approved = backend.approve_request(request["request_id"], actor="control",evidence_id="human-event-one",provenance=provenance)
        self.assertEqual("authorized", approved["state"])
        self.assertFalse(approved["execution_possible"])
        self.assertEqual("semantic.action.home.tv.power_off", approved["authorization"]["target"])
        record=self.store.get(approved["authorization"]["authorization_id"])
        self.assertEqual("issued",record["state"])
        self.assertEqual(["human-event-one"],record["token"]["approval_evidence_ids"])
        self.assertEqual({"human-event-one":provenance},record["token"]["approval_provenance"])
        approval=next(gate for gate in approved["gates"] if gate["kind"]=="approval")
        self.assertEqual("human-event-one",approval["evidence"]["evidence_id"])
        self.assertEqual(provenance,approval["evidence"]["provenance"])
        crash_window=ledger.get_request(request["request_id"])
        self.assertEqual("authorized",crash_window["state"])
        self.assertEqual(approved["authorization"]["authorization_id"],crash_window["authorization"]["authorization_id"])
        ledger.close()

    def test_step_up_requires_step_up_assurance(self):
        backend=self.backend()
        request=backend.request_action(action="home.tv.power_off",parameters={"summary":"Turn TV off","target":"living-room-tv","details":{}},context={},trusted_context={},requester="agent",idempotency_key="step",minimum_control="step_up")
        with self.assertRaisesRegex(ApprovalRejected,"assurance"):
            backend.approve_request(request["request_id"],actor="control",assurance="ask")
        approved=backend.approve_request(request["request_id"],actor="signed-human",assurance="step_up")
        self.assertEqual("authorized",approved["state"])

    def test_signed_approval_expiry_bounds_authorization_lifetime(self):
        backend=self.backend(); request=backend.request_action(action="home.tv.power_off",parameters={"summary":"Turn TV off","target":"living-room-tv","details":{}},context={},trusted_context={},requester="agent",idempotency_key="short-expiry")
        approved=backend.approve_request(request["request_id"],actor="signed-human",assurance="ask",evidence_id="short-lived",provenance={"transport":"ed25519","key_id":"owner-key","signed_at":99,"signature_sha256":"a"*64},expires_at=125)
        self.assertEqual(125,approved["authorization"]["expires_at"])

    def test_signed_approval_expiry_is_validated_and_clamped_to_gate_ttl(self):
        backend=self.backend(); request=backend.request_action(action="home.tv.power_off",parameters={"summary":"Turn TV off","target":"living-room-tv","details":{}},context={},trusted_context={},requester="agent",idempotency_key="expiry-validation")
        with self.assertRaisesRegex(ApprovalRejected,"expiry"):
            backend.approve_request(request["request_id"],actor="signed-human",expires_at=100)
        approved=backend.approve_request(request["request_id"],actor="signed-human",expires_at=10_000)
        approval=next(gate for gate in approved["gates"] if gate["kind"]=="approval")
        self.assertEqual(700,approval["evidence"]["expires_at"])
        self.assertEqual(400,approved["authorization"]["expires_at"])

    def test_approval_provenance_is_closed_and_non_secret(self):
        backend=self.backend(); request=backend.request_action(action="home.tv.power_off",parameters={"summary":"Turn TV off","target":"living-room-tv","details":{}},context={},trusted_context={},requester="agent",idempotency_key="provenance")
        with self.assertRaisesRegex(ApprovalRejected,"provenance"):
            backend.approve_request(request["request_id"],actor="control",provenance={"transport":"ed25519","raw_signature":"secret"})

    def test_read_and_prohibited_catalog_entries_are_not_requestable(self):
        backend = self.backend()
        for action in ("home.read", "system.shell.execute"):
            with self.subTest(action=action), self.assertRaises(Exception):
                backend.request_action(action=action, parameters={}, context={}, trusted_context={}, requester="agent", idempotency_key=action)


if __name__ == "__main__": unittest.main()
