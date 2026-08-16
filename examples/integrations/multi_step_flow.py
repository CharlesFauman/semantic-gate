#!/usr/bin/env python3
"""Agent-owned multi-step flow: each effect receives a separate decision."""
from __future__ import annotations

import hashlib
import json

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
    notifier=DeliveredNotifier(); backend=CoreBackend(build_policy(catalog,{"example-agent":{"role":"agent","enabled":True}}),approval_key=b"example-approval-key-material-32b",clock=lambda:100,notifier=notifier)
    events=[]
    build=backend.request_action(action="release.build",parameters={"summary":"Build artifact","target":"artifact-v1","details":{"source_digest":"source-001"}},context={"flow":"release"},trusted_context={"flow":"release"},requester="example-agent",idempotency_key="flow-build")
    events.append("build_waiting")
    build=backend.approve_request(build["request_id"],actor="example-human",assurance="ask")
    events.append("build_simulated")
    if build["state"]!="simulated": raise SystemExit("agent stopped after build")
    # The agent—not Semantic Gate—chooses to continue to the next effect.
    publish=backend.request_action(action="release.publish",parameters={"summary":"Publish artifact","target":"example-registry","details":{"artifact_digest":"artifact-001"}},context={"flow":"release"},trusted_context={"flow":"release"},requester="example-agent",idempotency_key="flow-publish")
    events.append("publish_waiting")
    assert publish["effective_control"]=="step_up"
    publish=backend.approve_request(publish["request_id"],actor="example-human",assurance="step_up")
    events.append("publish_simulated")
    assert publish["state"]=="simulated" and build["request_id"]!=publish["request_id"]
    print(json.dumps({"ok":True,"execution_enabled":False,"agent_owned_flow":True,"separate_request_ids":True,"events":events,"final_state":publish["state"],"notifications":len(notifier.events)},sort_keys=True))


if __name__=="__main__": main()
