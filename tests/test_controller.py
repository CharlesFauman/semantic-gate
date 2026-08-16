#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from semantic_gate.controller import GateControl, GateControlError
from semantic_gate.storage import Ledger


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
        request = {"request_id":f"req_{len(self.calls)}","request_hash":"h","action":action,"requester":requester,"state":"waiting_for_approval","created_at":100,"parameters":parameters,"context":context,"minimum_control":minimum_control,"gates":[]}
        self.requests[request["request_id"]] = request
        return dict(request)

    def get_request(self, request_id, requester=None):
        return dict(self.requests[request_id])

    def cancel_request(self, request_id, requester):
        self.requests[request_id]["state"] = "cancelled"
        return dict(self.requests[request_id])

    def approve_request(self, request_id, actor, assurance="ask"):
        self.requests[request_id]["state"] = "simulated"
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
            self.control.approve(request["request_id"], actor="hermes-mac", actor_role="agent")
        result = self.control.approve(request["request_id"], actor="control-panel", actor_role="admin")
        self.assertEqual("simulated", result["state"])
        self.assertFalse(result.get("execution_possible", False))
        self.assertEqual(["requested", "approved"], [event["event"] for event in self.ledger.audit_events(request["request_id"])])

    def test_persisted_terminal_request_remains_readable_after_backend_restart(self):
        request={"request_id":"old","request_hash":"h","action":"home.tv.power_off","requester":"hermes-mac","state":"expired","created_at":1,"updated_at":2,"parameters":{},"context":{},"gates":[]}
        self.ledger.record_request(request,event="expired_on_restart",actor="system")
        result=self.control.get_request("old",principal="hermes-mac")
        self.assertEqual("expired",result["state"])

    def test_request_idempotency_survives_backend_restart(self):
        payload={"action":"home.tv.power_off","parameters":{"target":"living-room"},"context":{"surface":"test"},"idempotency_key":"durable"}
        original=self.control.request_action(principal="hermes-mac",payload=payload,host_context={"node":"mac"})
        class RestartedBackend(FakeBackend):
            def request_action(self,**kwargs): raise AssertionError("backend must not be called for durable replay")
        restarted=GateControl(RestartedBackend(),self.ledger,clock=lambda:101)
        replay=restarted.request_action(principal="hermes-mac",payload=payload,host_context={"node":"mac"})
        self.assertEqual(original["request_id"],replay["request_id"])
        changed={**payload,"parameters":{"target":"other"}}
        with self.assertRaisesRegex(GateControlError,"different request"):
            restarted.request_action(principal="hermes-mac",payload=changed,host_context={"node":"mac"})

    def test_request_idempotency_is_reserved_before_backend_callbacks(self):
        second_ledger=Ledger(Path(self.tmp.name)/"ledger.sqlite3"); entered=threading.Event(); release=threading.Event()
        class BlockingBackend(FakeBackend):
            def request_action(self,**kwargs): entered.set(); release.wait(2); return super().request_action(**kwargs)
        backend=BlockingBackend(); first=GateControl(backend,self.ledger,clock=lambda:100); second=GateControl(backend,second_ledger,clock=lambda:100)
        payload={"action":"home.tv.power_off","parameters":{},"context":{},"idempotency_key":"atomic"}; outcomes=[]
        thread=threading.Thread(target=lambda:outcomes.append(first.request_action(principal="hermes-mac",payload=payload,host_context={})))
        thread.start(); self.assertTrue(entered.wait(1))
        with self.assertRaisesRegex(GateControlError,"in progress"):
            second.request_action(principal="hermes-mac",payload=payload,host_context={})
        release.set(); thread.join(); self.assertEqual(1,len(backend.calls)); second_ledger.close()

    def test_crash_after_idempotency_reservation_never_repeats_backend(self):
        class CrashingBackend(FakeBackend):
            def request_action(self,**kwargs): self.calls.append("attempted"); raise RuntimeError("crash after callback may have started")
        payload={"action":"home.tv.power_off","parameters":{},"context":{},"idempotency_key":"crash"}; crashing=CrashingBackend(); control=GateControl(crashing,self.ledger,clock=lambda:100)
        with self.assertRaises(RuntimeError): control.request_action(principal="hermes-mac",payload=payload,host_context={})
        restarted=FakeBackend(); retry=GateControl(restarted,self.ledger,clock=lambda:101)
        with self.assertRaisesRegex(GateControlError,"in progress"):
            retry.request_action(principal="hermes-mac",payload=payload,host_context={})
        self.assertEqual([],restarted.calls)

    def test_persisted_authorization_can_be_revoked_after_backend_restart(self):
        request={"request_id":"auth-request","request_hash":"h","action":"home.tv.power_off","requester":"hermes-mac","state":"authorized","created_at":1,"updated_at":2,"parameters":{},"context":{},"gates":[],"authorization":{"authorization_id":"auth-one","status":"issued"}}
        self.ledger.record_request(request,event="authorized",actor="human")
        class Store:
            def __init__(self): self.cancelled=[]
            def cancel(self,authorization_id,now): self.cancelled.append((authorization_id,now)); return {"state":"cancelled"}
        store=Store(); restarted=GateControl(FakeBackend(),self.ledger,clock=lambda:10,authorization_store=store)
        cancelled=restarted.cancel("auth-request",principal="hermes-mac")
        self.assertEqual("cancelled",cancelled["state"]); self.assertEqual([("auth-one",10)],store.cancelled)
        request["request_id"]="auth-deny"; request["state"]="authorized"; request["authorization"]["status"]="issued"
        self.ledger.record_request(request,event="authorized",actor="human")
        denied=restarted.deny("auth-deny",actor="admin",actor_role="admin")
        self.assertEqual("denied",denied["state"]); self.assertEqual("cancelled",denied["authorization"]["status"])

    def test_repeated_cancel_repairs_from_durable_cancelled_snapshot(self):
        request={"request_id":"already-cancelled","request_hash":"h","action":"home.tv.power_off","requester":"hermes-mac","state":"cancelled","created_at":1,"updated_at":2,"parameters":{},"context":{},"gates":[],"consumption_possible":False,"authorization":{"authorization_id":"auth-one","status":"cancelled"}}
        self.ledger.record_request(request,event="authorization_cancelled",actor="authorization-store")
        class LostBackend(FakeBackend):
            def cancel_request(self,*args,**kwargs): raise AssertionError("backend must not be called")
        result=GateControl(LostBackend(),self.ledger,clock=lambda:10).cancel("already-cancelled",principal="hermes-mac")
        self.assertEqual("cancelled",result["state"])

    def test_pending_request_can_be_cancelled_after_backend_restart(self):
        request={"request_id":"pending-restart","request_hash":"h","action":"home.tv.power_off","requester":"hermes-mac","state":"waiting_for_approval","created_at":1,"updated_at":2,"parameters":{},"context":{},"gates":[]}
        self.ledger.record_request(request,event="requested",actor="hermes-mac")
        class LostBackend(FakeBackend):
            def cancel_request(self,*args,**kwargs): raise KeyError("process-local request lost")
        cancelled=GateControl(LostBackend(),self.ledger,clock=lambda:10).cancel("pending-restart",principal="hermes-mac")
        self.assertEqual("cancelled",cancelled["state"]); self.assertEqual("cancelled",self.ledger.get_request("pending-restart")["state"])

    def test_request_reads_repair_stale_authorization_projection(self):
        request={"request_id":"stale-auth","request_hash":"h","action":"home.tv.power_off","requester":"hermes-mac","state":"authorized","created_at":1,"updated_at":2,"parameters":{},"context":{},"gates":[],"consumption_possible":True,"authorization":{"authorization_id":"auth-stale","status":"issued"}}
        self.ledger.record_request(request,event="authorized",actor="human")
        class Store:
            def get(self,authorization_id): return {"authorization_id":authorization_id,"state":"executed","receipt":{"order_id":"one"},"updated_at":9}
        control=GateControl(FakeBackend(),self.ledger,clock=lambda:10,authorization_store=Store())
        repaired=control.get_request("stale-auth",principal="hermes-mac")
        self.assertEqual("executed",repaired["state"]); self.assertFalse(repaired["consumption_possible"])
        self.assertEqual("executed",self.ledger.get_request("stale-auth")["state"])

    def test_request_read_recovers_orphaned_authorization_snapshot(self):
        waiting={"request_id":"orphan","request_hash":"h","action":"home.tv.power_off","requester":"hermes-mac","state":"waiting_for_approval","created_at":1,"updated_at":2,"parameters":{},"context":{},"gates":[]}
        self.ledger.record_request(waiting,event="requested",actor="hermes-mac")
        authorized={**waiting,"state":"authorized","updated_at":3,"consumption_possible":True,"authorization":{"authorization_id":"auth-orphan","status":"issued"}}
        class Store:
            def get_for_request(self,request_id): return {"state":"issued","updated_at":3,"receipt":None,"request_snapshot":authorized}
        recovered=GateControl(FakeBackend(),self.ledger,clock=lambda:10,authorization_store=Store()).get_request("orphan",principal="hermes-mac")
        self.assertEqual("authorized",recovered["state"]); self.assertEqual("auth-orphan",recovered["authorization"]["authorization_id"])

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


if __name__ == "__main__":
    unittest.main()
