#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
import subprocess
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAS_CRYPTO=True
except ImportError:
    serialization=None; Ed25519PrivateKey=None; HAS_CRYPTO=False

from semantic_gate.approvals import ApprovalTransportError,Ed25519ApprovalRoster,SignedApprovalBridge,sign_approval


@unittest.skipUnless(HAS_CRYPTO,"install semantic-gate[approvals]")
class Ed25519ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.private=Ed25519PrivateKey.generate(); public=self.private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.roster=Ed25519ApprovalRoster({"owner-key":{"actor":"human:owner","public_key":base64.b64encode(public).decode(),"assurances":["ask","step_up"]}},clock=lambda:110,max_age_seconds=60)
        self.request={"request_id":"req_one","request_hash":"r"*64,"created_at":100,"effective_control":"step_up"}

    def decision(self,**changes):
        value={"evidence_id":"human-event-1","request_id":"req_one","request_hash":"r"*64,"actor":"human:owner","decision":"approve","assurance":"step_up","key_id":"owner-key","signed_at":105,"expires_at":150}
        value.update(changes); return sign_approval(value,self.private)

    def test_valid_signature_proves_enrolled_human_and_step_up(self):
        verified=self.roster.verify(self.decision(),self.request)
        self.assertEqual({"actor":"human:owner","assurance":"step_up","evidence_id":"human-event-1"},verified)

    def test_tamper_spoof_stale_unknown_and_downgrade_fail_closed(self):
        cases=[]
        tampered=self.decision(); tampered["request_hash"]="x"*64; cases.append(tampered)
        cases.append(self.decision(actor="service:notifier"))
        cases.append(self.decision(signed_at=1))
        cases.append(self.decision(key_id="unknown"))
        cases.append(self.decision(assurance="ask"))
        for item in cases:
            with self.subTest(item=item),self.assertRaises(ApprovalTransportError): self.roster.verify(item,self.request)

    def test_roster_and_private_key_file_formats_are_real_and_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            private_path=Path(tmp)/"approval.pem"; roster_path=Path(tmp)/"roster.json"
            private_path.write_bytes(self.private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            roster_path.write_text(json.dumps({"keys":{"owner-key":{"actor":"human:owner","public_key":self.roster.export_public_key("owner-key"),"assurances":["step_up"]}}}))
            loaded=Ed25519ApprovalRoster.from_file(roster_path,clock=lambda:110)
            decision=sign_approval({"evidence_id":"two","request_id":"req_one","request_hash":"r"*64,"actor":"human:owner","decision":"approve","assurance":"step_up","key_id":"owner-key","signed_at":105,"expires_at":150},private_path)
            self.assertEqual("human:owner",loaded.verify(decision,self.request)["actor"])

    def test_host_only_bridge_forwards_only_verified_actor_and_assurance(self):
        class Backend:
            def __init__(self,request): self.request=request; self.calls=[]
            def get_request(self,request_id): return self.request
            def approve_request(self,request_id,actor,assurance,evidence_id=None,provenance=None,expires_at=None): self.calls.append((request_id,actor,assurance,evidence_id,provenance,expires_at)); return {"state":"authorized"}
        backend=Backend(self.request); bridge=SignedApprovalBridge(self.roster,backend)
        decision=self.decision(); self.assertEqual("authorized",bridge.approve(decision)["state"])
        provenance={"transport":"ed25519","key_id":"owner-key","signed_at":105,"signature_sha256":hashlib.sha256(base64.b64decode(decision["signature"])).hexdigest()}
        self.assertEqual([("req_one","human:owner","step_up","human-event-1",provenance,150)],backend.calls)
        with self.assertRaises(ApprovalTransportError): bridge.approve(self.decision(actor="service:notifier"))
        self.assertEqual(1,len(backend.calls))

    def test_runnable_public_ed25519_flow(self):
        root=Path(__file__).resolve().parents[1]
        completed=subprocess.run([sys.executable,str(root/"examples/integrations/ed25519_approval_flow.py")],cwd=root,text=True,capture_output=True,check=True,env={"PYTHONPATH":str(root/"src")})
        result=json.loads(completed.stdout); self.assertTrue(result["ok"]); self.assertEqual("authorized",result["state"])


if __name__=="__main__": unittest.main()
