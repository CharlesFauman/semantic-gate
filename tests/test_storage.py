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
        self.ledger.record_audit(event="custom",actor="system",at=101,metadata={"safe":True},request_id="req_1")
        self.ledger.close()
        reopened = Ledger(self.path)
        try:
            self.assertEqual("waiting_for_approval", reopened.get_request("req_1")["state"])
            events = reopened.audit_events("req_1")
            self.assertEqual(["requested","custom"], [event["event"] for event in events])
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

    def test_audit_observations_are_idempotent_durable_and_conflict_safe(self):
        observation={
            "event_id":"tool-call:abc:attempted",
            "principal":"hermes-mac",
            "phase":"attempted",
            "operation":"ha_call_service",
            "semantic_class":"home.control.unclassified",
            "outcome":"started",
            "occurred_at":100,
            "received_at":101,
            "metadata":{"surface":"hermes","node":"mac"},
        }
        first=self.ledger.record_observation(observation)
        self.assertEqual(first,self.ledger.record_observation(dict(observation)))
        self.assertEqual(["permission_observed"],[event["event"] for event in self.ledger.audit_events()])
        with self.assertRaisesRegex(ValueError,"conflicting observation"):
            self.ledger.record_observation({**observation,"outcome":"failed"})
        self.ledger.close()
        reopened=Ledger(self.path)
        try:
            self.assertEqual(first,reopened.get_observation(observation["event_id"],principal="hermes-mac"))
        finally:
            reopened.close()

    def test_observation_ids_are_principal_scoped_and_storage_is_bounded(self):
        self.ledger.close()
        self.ledger=Ledger(self.path,max_observations=2,max_audit_events=3)
        base={"event_id":"same","phase":"completed","operation":"terminal","semantic_class":"compute.exec.arbitrary","outcome":"succeeded","occurred_at":1,"received_at":2,"metadata":{}}
        self.ledger.record_observation({**base,"principal":"one"})
        self.ledger.record_observation({**base,"principal":"two"})
        self.ledger.record_observation({**base,"event_id":"new","principal":"one"})
        self.assertIsNone(self.ledger.get_observation("same",principal="one"))
        self.assertIsNotNone(self.ledger.get_observation("same",principal="two"))
        self.assertLessEqual(len(self.ledger.audit_events(limit=100)),3)

    def test_concurrent_duplicate_observation_commits_once(self):
        other=Ledger(self.path); barrier=__import__("threading").Barrier(2); results=[]
        base={"event_id":"race","principal":"agent","phase":"completed","operation":"terminal","semantic_class":"compute.exec.arbitrary","outcome":"succeeded","occurred_at":1,"metadata":{}}
        def write(ledger,received):
            barrier.wait(); results.append(ledger.record_observation({**base,"received_at":received}))
        threads=[__import__("threading").Thread(target=write,args=(self.ledger,2)),__import__("threading").Thread(target=write,args=(other,3))]
        try:
            [thread.start() for thread in threads]; [thread.join() for thread in threads]
            self.assertEqual(2,len(results)); self.assertEqual(results[0],results[1])
            self.assertEqual(1,len([event for event in self.ledger.audit_events() if event["event"]=="permission_observed"]))
        finally: other.close()


if __name__ == "__main__":
    unittest.main()
