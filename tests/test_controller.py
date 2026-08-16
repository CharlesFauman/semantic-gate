#!/usr/bin/env python3
from __future__ import annotations

import tempfile
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

    def request_action(self, *, action, parameters, context, trusted_context, requester, idempotency_key):
        self.calls.append((action, requester, trusted_context))
        request = {"request_id":f"req_{len(self.calls)}","request_hash":"h","action":action,"requester":requester,"state":"waiting_for_approval","created_at":100,"parameters":parameters,"context":context,"gates":[]}
        self.requests[request["request_id"]] = request
        return dict(request)

    def get_request(self, request_id, requester=None):
        return dict(self.requests[request_id])

    def cancel_request(self, request_id, requester):
        self.requests[request_id]["state"] = "cancelled"
        return dict(self.requests[request_id])

    def approve_request(self, request_id, actor):
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
        self.assertEqual(("home.tv.power_off", "hermes-mac", {"direct_user_request":False,"surface":"mcp"}), self.backend.calls[0])
        self.assertNotIn("trusted_context", result)
        self.assertEqual("waiting_for_approval", self.ledger.get_request(result["request_id"])["state"])
        for forbidden in ("requester", "trusted_context"):
            payload = {"action":"home.tv.power_off","parameters":{},"context":{},"idempotency_key":forbidden,forbidden:"forged"}
            with self.subTest(forbidden=forbidden), self.assertRaisesRegex(GateControlError, "unknown request field"):
                self.control.request_action(principal="hermes-mac", payload=payload, host_context={})

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
