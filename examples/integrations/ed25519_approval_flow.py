#!/usr/bin/env python3
"""Runnable Ed25519 human-approval flow for the optional approvals extra."""
from __future__ import annotations

import base64
import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from semantic_gate.approvals import Ed25519ApprovalRoster,SignedApprovalBridge,sign_approval
from semantic_gate.authorization import SQLiteAuthorizationStore
from semantic_gate.catalog import build_policy
from semantic_gate.coordinator import CoreBackend


def main() -> None:
    private=Ed25519PrivateKey.generate()
    public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    roster=Ed25519ApprovalRoster({"owner-key":{"actor":"human:owner","public_key":base64.b64encode(public).decode(),"assurances":["ask"]}},clock=lambda:110,max_age_seconds=60)
    catalog={"version":1,"actions":{"home.example.confirm":{"domain":"home","risk":"R2","effect":"external_write","summary":"Confirm example action","approval":"separate_confirmation","privacy_classes":[],"constraints":[]}}}
    principals={"example-agent":{"role":"agent","enabled":True},"human-owner":{"role":"admin","enabled":True}}
    with tempfile.TemporaryDirectory() as tmp:
        store=SQLiteAuthorizationStore(Path(tmp)/"gate.sqlite3")
        backend=CoreBackend(build_policy(catalog,principals),approval_key=b"a"*32,authorization_key=b"b"*32,authorization_store=store,clock=lambda:110)
        request=backend.request_action(action="home.example.confirm",parameters={"summary":"Confirm example","target":"example","details":{}},context={},trusted_context={},requester="example-agent",idempotency_key="ed25519-example")
        decision=sign_approval({"evidence_id":"human-event-example","request_id":request["request_id"],"request_hash":request["request_hash"],"actor":"human:owner","decision":"approve","assurance":"ask","key_id":"owner-key","signed_at":110,"expires_at":150},private)
        authorized=SignedApprovalBridge(roster,backend).approve(decision)
        record=store.get(authorized["authorization"]["authorization_id"])
        assert authorized["state"]=="authorized" and record["token"]["approval_evidence_ids"]==["human-event-example"]
        print(json.dumps({"ok":True,"state":authorized["state"],"actor":"human:owner","evidence_id":"human-event-example","authorization_issued":True},sort_keys=True))
        store.close()


if __name__=="__main__": main()
