#!/usr/bin/env python3
from __future__ import annotations

import unittest
import hashlib

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

    @staticmethod
    def delivered(at=100):
        class Delivered:
            def notify(self,request,gate):
                return {"delivered":True,"notification_id":"notice","request_id":request["request_id"],"request_hash":request["request_hash"],"notification_gate_id":gate["id"],"recipient":gate["recipient"],"template_hash":hashlib.sha256(gate["template"].encode()).hexdigest(),"delivered_at":at}
        return Delivered()

    def test_real_core_waits_for_host_approval_then_only_simulates(self):
        backend = CoreBackend(build_policy(self.catalog, self.principals), approval_key=bytes.fromhex("22" * 32), clock=lambda: 100,notifier=self.delivered())
        request = backend.request_action(
            action="home.tv.power_off",
            parameters={"summary":"Turn TV off","target":"living-room-tv","details":{}},
            context={"surface":"test"}, trusted_context={"surface":"test"},
            requester="agent", idempotency_key="core-one",
        )
        self.assertEqual("waiting_for_approval", request["state"])
        self.assertFalse(request["execution_possible"])
        approval=next(g for g in request["gates"] if g["kind"]=="approval" and g["status"]=="waiting")
        challenge={"request_id":request["request_id"],"request_hash":request["request_hash"],"approval_gate_id":approval["id"],"expires_at":request["created_at"]+approval["evidence"]["ttl_seconds"]}
        approved = backend.approve_request(request["request_id"], actor="control", challenge=challenge)
        self.assertEqual("simulated", approved["state"])
        self.assertFalse(approved["execution_possible"])
        self.assertEqual("semantic.action.home.tv.power_off", approved["would_call"]["tool"])

    def test_approval_deadline_starts_when_the_request_reaches_human_review(self):
        now=[100]
        class AdvancingNotifier:
            def notify(self,request,gate):
                now[0]=150
                return {"delivered":True,"notification_id":"notice","request_id":request["request_id"],"request_hash":request["request_hash"],"notification_gate_id":gate["id"],"recipient":gate["recipient"],"template_hash":hashlib.sha256(gate["template"].encode()).hexdigest(),"delivered_at":150}
        backend=CoreBackend(build_policy(self.catalog,self.principals),approval_key=bytes.fromhex("22"*32),clock=lambda:now[0],notifier=AdvancingNotifier())
        request=backend.request_action(action="home.tv.power_off",parameters={"summary":"Turn TV off","target":"living-room-tv","details":{}},context={},trusted_context={},requester="agent",idempotency_key="deadline")
        approval=next(g for g in request["gates"] if g["kind"]=="approval" and g["status"]=="waiting")
        self.assertEqual(150+approval["evidence"]["ttl_seconds"],request["approval_challenge"]["expires_at"])

    def test_approval_deadline_is_delivery_anchored_and_absolutely_capped(self):
        now=[100]
        class DeliveredNearCap:
            def notify(self,request,gate):
                now[0]=100+CoreBackend.APPROVAL_ABSOLUTE_CAP_SECONDS-10
                return {"delivered":True,"notification_id":"notice","request_id":request["request_id"],"request_hash":request["request_hash"],"notification_gate_id":gate["id"],"recipient":gate["recipient"],"template_hash":hashlib.sha256(gate["template"].encode()).hexdigest(),"delivered_at":now[0]}
        backend=CoreBackend(build_policy(self.catalog,self.principals),approval_key=bytes.fromhex("22"*32),clock=lambda:now[0],notifier=DeliveredNearCap())
        request=backend.request_action(action="home.tv.power_off",parameters={"summary":"Turn TV off","target":"living-room-tv","details":{}},context={},trusted_context={},requester="agent",idempotency_key="absolute-cap")
        self.assertEqual(request["created_at"]+CoreBackend.APPROVAL_ABSOLUTE_CAP_SECONDS,request["approval_challenge"]["expires_at"])
        now[0]=request["approval_challenge"]["expires_at"]
        with self.assertRaisesRegex(ApprovalRejected,"expired"):
            backend.approve_request(request["request_id"],actor="control",challenge=request["approval_challenge"])

    def test_undelivered_notification_has_no_actionable_challenge(self):
        class Pending:
            def notify(self,request,gate):
                return {"delivered":False,"notification_id":"notice","request_id":request["request_id"],"request_hash":request["request_hash"],"notification_gate_id":gate["id"],"recipient":gate["recipient"],"template_hash":hashlib.sha256(gate["template"].encode()).hexdigest(),"delivered_at":None}
        backend=CoreBackend(build_policy(self.catalog,self.principals),approval_key=bytes.fromhex("22"*32),clock=lambda:100,notifier=Pending())
        request=backend.request_action(action="home.tv.power_off",parameters={"summary":"Turn TV off","target":"living-room-tv","details":{}},context={},trusted_context={},requester="agent",idempotency_key="pending")
        self.assertNotIn("approval_challenge",request)

    def test_password_backend_cannot_claim_step_up_assurance(self):
        backend=CoreBackend(build_policy(self.catalog,self.principals),approval_key=bytes.fromhex("22"*32),clock=lambda:100,notifier=self.delivered())
        request=backend.request_action(action="home.tv.power_off",parameters={"summary":"Turn TV off","target":"living-room-tv","details":{}},context={},trusted_context={},requester="agent",idempotency_key="step",minimum_control="step_up")
        approval=next(g for g in request["gates"] if g["kind"]=="approval" and g["status"]=="waiting")
        challenge={"request_id":request["request_id"],"request_hash":request["request_hash"],"approval_gate_id":approval["id"],"expires_at":request["created_at"]+approval["evidence"]["ttl_seconds"]}
        with self.assertRaisesRegex(ApprovalRejected,"step-up"):
            backend.approve_request(request["request_id"],actor="control",challenge=challenge)

    def test_backend_rejects_mismatched_expired_and_replayed_decisions(self):
        now=[100]
        backend=CoreBackend(build_policy(self.catalog,self.principals),approval_key=bytes.fromhex("22"*32),clock=lambda:now[0],notifier=self.delivered())
        request=backend.request_action(action="home.tv.power_off",parameters={"summary":"Turn TV off","target":"living-room-tv","details":{}},context={},trusted_context={},requester="agent",idempotency_key="deny")
        approval=next(g for g in request["gates"] if g["kind"]=="approval" and g["status"]=="waiting")
        exact={"request_id":request["request_id"],"request_hash":request["request_hash"],"approval_gate_id":approval["id"],"expires_at":request["created_at"]+approval["evidence"]["ttl_seconds"]}
        with self.assertRaises(ApprovalRejected): backend.deny_request(request["request_id"],actor="control",challenge={**exact,"request_hash":"bad"})
        now[0]=exact["expires_at"]
        with self.assertRaisesRegex(ApprovalRejected,"expired"): backend.deny_request(request["request_id"],actor="control",challenge=exact)
        now[0]=100
        self.assertEqual("denied",backend.deny_request(request["request_id"],actor="control",challenge=exact)["state"])
        with self.assertRaisesRegex(ApprovalRejected,"awaiting"): backend.deny_request(request["request_id"],actor="control",challenge=exact)

    def test_read_and_prohibited_catalog_entries_are_not_requestable(self):
        backend = CoreBackend(build_policy(self.catalog, self.principals), approval_key=bytes.fromhex("22" * 32), clock=lambda: 100)
        for action in ("home.read", "system.shell.execute"):
            with self.subTest(action=action), self.assertRaises(Exception):
                backend.request_action(action=action, parameters={}, context={}, trusted_context={}, requester="agent", idempotency_key=action)


if __name__ == "__main__":
    unittest.main()
