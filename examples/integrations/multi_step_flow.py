#!/usr/bin/env python3
"""Agent-owned multi-step flow: each effect receives a separate authorization."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile

from semantic_gate.authorization import SQLiteAuthorizationStore
from semantic_gate.catalog import build_policy
from semantic_gate.coordinator import CoreBackend


class DeliveredNotifier:
    def __init__(self): self.events=[]
    def notify(self,request: dict,gate: dict) -> dict:
        event={"notification_id":"notice-"+request["request_id"],"request_id":request["request_id"],"request_hash":request["request_hash"],"notification_gate_id":gate["id"],"recipient":gate["recipient"],"template_hash":hashlib.sha256(gate["template"].encode()).hexdigest(),"delivered_at":100,"delivered":True}
        self.events.append(event); return event


def main() -> None:
    catalog={"version":1,"actions":{
        "release.build":{"domain":"release","risk":"R2","effect":"private_write","summary":"Build one reviewed artifact.","approval":"separate_confirmation","privacy_classes":[],"constraints":["Exact source digest required."]},
        "release.publish":{"domain":"release","risk":"R3","effect":"external_write","summary":"Publish one reviewed artifact.","approval":"step_up","privacy_classes":[],"constraints":["Exact artifact digest and destination required."]},
    }}
    with tempfile.TemporaryDirectory() as tmp:
        store=SQLiteAuthorizationStore(Path(tmp)/"authorization.sqlite3")
        try:
            notifier=DeliveredNotifier(); backend=CoreBackend(build_policy(catalog,{"example-agent":{"role":"agent","enabled":True}}),approval_key=b"example-approval-key-material-32b",authorization_key=b"example-authorization-key-material",authorization_store=store,clock=lambda:100,notifier=notifier)
            events=[]
            build=backend.request_action(action="release.build",parameters={"summary":"Build artifact","target":"artifact-v1","details":{"source_digest":"source-001"}},context={"flow":"release"},trusted_context={"flow":"release"},requester="example-agent",idempotency_key="flow-build")
            events.append("build_waiting")
            build=backend.approve_request(build["request_id"],actor="example-human",assurance="ask")
            events.append("build_authorized")
            if build["state"]!="authorized": raise SystemExit("agent stopped after build authorization")
            # The agent—not Semantic Gate—chooses whether to consume build authorization
            # and whether to propose the next effect. This example leaves both unconsumed.
            publish=backend.request_action(action="release.publish",parameters={"summary":"Publish artifact","target":"example-registry","details":{"artifact_digest":"artifact-001"}},context={"flow":"release"},trusted_context={"flow":"release"},requester="example-agent",idempotency_key="flow-publish")
            events.append("publish_waiting")
            assert publish["effective_control"]=="step_up"
            publish=backend.approve_request(publish["request_id"],actor="example-human",assurance="step_up")
            events.append("publish_authorized")
            assert publish["state"]=="authorized" and build["request_id"]!=publish["request_id"]
            ids=[build["authorization"]["authorization_id"],publish["authorization"]["authorization_id"]]
            assert all(store.get(item)["state"]=="issued" for item in ids)
            print(json.dumps({"ok":True,"execution_enabled":False,"agent_owned_flow":True,"separate_request_ids":True,"separate_authorization_ids":len(set(ids))==2,"authorization_consumed":False,"events":events,"final_state":publish["state"],"notifications":len(notifier.events)},sort_keys=True))
        finally: store.close()


if __name__=="__main__": main()
