#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from semantic_gate.storage import Ledger


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "gate.sqlite3"
        self.ledger = Ledger(self.path)

    def tearDown(self):
        self.ledger.close()
        self.tmp.cleanup()

    def test_request_snapshots_and_audit_survive_restart(self):
        request = {"request_id":"req_1","action":"home.tv.power_off","requester":"hermes-mac","state":"waiting_for_approval","created_at":100}
        self.ledger.record_request(request, event="requested", actor="hermes-mac")
        self.ledger.close()
        reopened = Ledger(self.path)
        try:
            self.assertEqual("waiting_for_approval", reopened.get_request("req_1")["state"])
            events = reopened.audit_events("req_1")
            self.assertEqual(["requested"], [event["event"] for event in events])
            self.assertNotIn("secret", str(events))
        finally:
            reopened.close()

    def test_restart_expires_unresolved_requests_without_reviving_them(self):
        for state in ("processing", "waiting_for_approval"):
            self.ledger.record_request({"request_id":f"req_{state}","action":"x.y","requester":"agent","state":state,"created_at":100}, event="requested", actor="agent")
        self.ledger.record_request({"request_id":"req_done","action":"x.y","requester":"agent","state":"simulated","created_at":100}, event="simulated", actor="system")
        expired = self.ledger.expire_unresolved(now=200)
        self.assertEqual(2, expired)
        self.assertEqual("expired", self.ledger.get_request("req_processing")["state"])
        self.assertEqual("simulated", self.ledger.get_request("req_done")["state"])

    def test_pause_and_revocation_are_restrictive_and_persistent(self):
        self.ledger.set_control("pause_all", True, actor="control-panel", now=10)
        self.ledger.set_control("paused_domains", ["purchase", "communication"], actor="control-panel", now=11)
        self.ledger.set_control("revoked_principals", ["codex"], actor="control-panel", now=12)
        self.assertTrue(self.ledger.controls()["pause_all"])
        self.ledger.close()
        reopened = Ledger(self.path)
        try:
            controls = reopened.controls()
            self.assertEqual(["purchase", "communication"], controls["paused_domains"])
            self.assertEqual(["codex"], controls["revoked_principals"])
        finally:
            reopened.close()


if __name__ == "__main__":
    unittest.main()
