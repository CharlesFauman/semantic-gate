#!/usr/bin/env python3
"""Runnable Buzz-style approval flow with an explicit verified-transport boundary."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile

from semantic_gate.authorization import SQLiteAuthorizationStore
from semantic_gate.catalog import build_policy
from semantic_gate.coordinator import CoreBackend


class Clock:
    def __init__(self,now: int=2_000_000_000): self.now=now
    def __call__(self) -> int: return self.now


class UnsignedBuzzTransportStub:
    """Offline behavioral stub; it does NOT implement Buzz cryptography."""
    def __init__(self): self.messages={}; self._verified_reactions={}
    def post(self,content: str) -> str:
        event_id=hashlib.sha256(content.encode()).hexdigest(); self.messages[event_id]=content; return event_id
    def add_transport_verified_reaction(self,event_id: str,emoji: str,signer: str,verified_at: int) -> None:
        # In production this method is called only after the Buzz adapter has
        # cryptographically verified event/reaction signatures and signer enrollment.
        self._verified_reactions.setdefault(event_id,[]).append({"emoji":emoji,"signer":signer,"verified_at":verified_at,"transport_verified":True})
    def verified_reactions(self,event_id: str) -> list[dict]: return list(self._verified_reactions.get(event_id,[]))


class BuzzNotifier:
    def __init__(self,buzz: UnsignedBuzzTransportStub,clock: Clock): self.buzz=buzz; self.clock=clock
    def notify(self,request: dict,gate: dict) -> dict:
        event_id=self.buzz.post(f"Review {request['action']} request {request['request_id']}")
        return {"notification_id":event_id,"request_id":request["request_id"],"request_hash":request["request_hash"],"notification_gate_id":gate["id"],"recipient":gate["recipient"],"template_hash":hashlib.sha256(gate["template"].encode()).hexdigest(),"delivered_at":self.clock(),"delivered":True}


class BuzzApprovalBridge:
    """Consumes only reactions already authenticated by the transport adapter."""
    def __init__(self,backend: CoreBackend,buzz: UnsignedBuzzTransportStub,allowed_signers: set[str],clock: Clock):
        self.backend=backend; self.buzz=buzz; self.allowed_signers=allowed_signers; self.clock=clock
    def scan(self,request_id: str) -> bool:
        request=self.backend.get_request(request_id)
        notice=next(g for g in request["gates"] if g["kind"]=="notify")["evidence"]["notification_id"]
        approval=next(g for g in request["gates"] if g["kind"]=="approval" and g["status"]=="waiting")
        expires_at=request["created_at"]+int(approval["evidence"]["ttl_seconds"])
        valid=[]
        for reaction in self.buzz.verified_reactions(notice):
            if set(reaction)!={"emoji","signer","verified_at","transport_verified"}: continue
            if reaction["transport_verified"] is not True or reaction["emoji"]!="👍": continue
            if reaction["signer"] not in self.allowed_signers: continue
            if type(reaction["verified_at"]) is not int or not request["created_at"]<=reaction["verified_at"]<=self.clock()<=expires_at: continue
            valid.append(reaction)
        if not valid: return False
        self.backend.approve_request(request_id,actor="buzz:"+valid[0]["signer"],assurance="step_up")
        return True


def main() -> None:
    clock=Clock(); buzz=UnsignedBuzzTransportStub()
    catalog={"version":1,"actions":{"document.publish":{"domain":"document","risk":"R2","effect":"external_write","summary":"Publish one reviewed document.","approval":"separate_confirmation","privacy_classes":[],"constraints":["Exact document and destination required."]}}}
    with tempfile.TemporaryDirectory() as tmp:
        store=SQLiteAuthorizationStore(Path(tmp)/"authorization.sqlite3")
        try:
            backend=CoreBackend(build_policy(catalog,{"example-agent":{"role":"agent","enabled":True}}),approval_key=b"example-approval-key-material-32b",authorization_key=b"example-authorization-key-material",authorization_store=store,clock=clock,notifier=BuzzNotifier(buzz,clock))
            request=backend.request_action(action="document.publish",parameters={"summary":"Publish reviewed guide","target":"example-site","details":{"document_id":"guide-v1"}},context={"surface":"example"},trusted_context={"surface":"example"},requester="example-agent",idempotency_key="buzz-flow-1",minimum_control="step_up")
            notice=next(g for g in request["gates"] if g["kind"]=="notify")["evidence"]["notification_id"]
            bridge=BuzzApprovalBridge(backend,buzz,{"owner-key"},clock)
            buzz.add_transport_verified_reaction(notice,"👍","untrusted-key",clock())
            assert bridge.scan(request["request_id"]) is False
            buzz.add_transport_verified_reaction(notice,"👍","owner-key",clock())
            assert bridge.scan(request["request_id"]) is True
            result=backend.get_request(request["request_id"])
            authorization=result["authorization"]
            assert result["state"]=="authorized" and result["effective_control"]=="step_up"
            assert store.get(authorization["authorization_id"])["state"]=="issued"
            print(json.dumps({"ok":True,"execution_enabled":False,"state":result["state"],"effective_control":result["effective_control"],"authorization_issued":True,"authorization_consumed":False,"verified_transport_boundary":True,"buzz_signature_verification_implemented":False,"trusted_reaction_accepted":True,"untrusted_reaction_rejected":True},sort_keys=True))
        finally: store.close()


if __name__=="__main__": main()
