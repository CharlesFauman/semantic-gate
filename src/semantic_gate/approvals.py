#!/usr/bin/env python3
"""Optional Ed25519 human-approval transport with enrolled public-key identities."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any,Mapping


class ApprovalTransportError(ValueError):
    pass


FIELDS={"evidence_id","request_id","request_hash","actor","decision","assurance","key_id","signed_at","expires_at"}
SIGNED_FIELDS=FIELDS|{"signature"}
RANK={"ask":1,"step_up":2}


def _canonical(value: Any) -> bytes:
    try: return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")
    except (TypeError,ValueError,OverflowError,RecursionError) as error: raise ApprovalTransportError("approval must contain strict JSON") from error


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
    except ImportError as error: raise ApprovalTransportError("install semantic-gate[approvals] for Ed25519 support") from error
    return InvalidSignature,serialization,Ed25519PrivateKey,Ed25519PublicKey


def _private_key(value):
    _,serialization,Ed25519PrivateKey,_=_crypto()
    if isinstance(value,Ed25519PrivateKey): return value
    if isinstance(value,(str,Path)):
        try: loaded=serialization.load_pem_private_key(Path(value).read_bytes(),password=None)
        except Exception as error: raise ApprovalTransportError("private key file is invalid") from error
        if not isinstance(loaded,Ed25519PrivateKey): raise ApprovalTransportError("private key is not Ed25519")
        return loaded
    raise ApprovalTransportError("private key must be an Ed25519 key or PEM path")


def sign_approval(decision: Mapping[str,Any],private_key) -> dict:
    if not isinstance(decision,Mapping) or set(decision)!=FIELDS: raise ApprovalTransportError("approval decision fields are malformed")
    body=json.loads(_canonical(decision)); signature=_private_key(private_key).sign(_canonical(body))
    body["signature"]=base64.b64encode(signature).decode("ascii"); return body


class Ed25519ApprovalRoster:
    def __init__(self,keys: Mapping[str,Mapping[str,Any]],*,clock,max_age_seconds: int=300):
        if type(max_age_seconds) is not int or max_age_seconds<1: raise ValueError("max_age_seconds must be positive")
        self.clock=clock; self.max_age_seconds=max_age_seconds; self.keys={}
        _,_,_,Ed25519PublicKey=_crypto()
        if not isinstance(keys,Mapping) or not keys: raise ApprovalTransportError("approval roster must contain keys")
        for key_id,record in keys.items():
            if not isinstance(key_id,str) or not key_id or not isinstance(record,Mapping) or set(record)!={"actor","public_key","assurances"}: raise ApprovalTransportError("approval roster entry is malformed")
            actor=record["actor"]; assurances=record["assurances"]
            if not isinstance(actor,str) or not actor.startswith("human:"): raise ApprovalTransportError("approval actor must be an enrolled human identity")
            if not isinstance(assurances,list) or not assurances or any(item not in RANK for item in assurances) or len(assurances)!=len(set(assurances)): raise ApprovalTransportError("approval assurances are invalid")
            try: raw=base64.b64decode(record["public_key"],validate=True); public=Ed25519PublicKey.from_public_bytes(raw)
            except Exception as error: raise ApprovalTransportError("approval public key is invalid") from error
            self.keys[key_id]={"actor":actor,"public_key":public,"public_key_text":record["public_key"],"assurances":set(assurances)}

    @classmethod
    def from_file(cls,path: str|Path,*,clock,max_age_seconds: int=300):
        try: document=json.loads(Path(path).read_text())
        except Exception as error: raise ApprovalTransportError("approval roster file is invalid") from error
        if not isinstance(document,dict) or set(document)!={"keys"}: raise ApprovalTransportError("approval roster document is malformed")
        return cls(document["keys"],clock=clock,max_age_seconds=max_age_seconds)

    def export_public_key(self,key_id: str) -> str:
        record=self.keys.get(key_id)
        if record is None: raise ApprovalTransportError("approval key is unknown")
        return record["public_key_text"]

    def verify(self,evidence: Mapping[str,Any],request: Mapping[str,Any]) -> dict:
        if not isinstance(evidence,Mapping) or set(evidence)!=SIGNED_FIELDS: raise ApprovalTransportError("signed approval fields are malformed")
        key=self.keys.get(evidence.get("key_id"))
        if key is None: raise ApprovalTransportError("approval key is unknown")
        if evidence.get("actor")!=key["actor"] or evidence.get("decision")!="approve": raise ApprovalTransportError("approval actor or decision is invalid")
        assurance=evidence.get("assurance"); required=request.get("effective_control","ask")
        if assurance not in key["assurances"] or assurance not in RANK or required not in RANK or RANK[assurance]<RANK[required]: raise ApprovalTransportError("approval assurance is insufficient")
        if evidence.get("request_id")!=request.get("request_id") or evidence.get("request_hash")!=request.get("request_hash"): raise ApprovalTransportError("approval is bound to a different request")
        now=int(self.clock()); signed_at=evidence.get("signed_at"); expires_at=evidence.get("expires_at")
        if type(signed_at) is not int or type(expires_at) is not int or not request.get("created_at",0)<=signed_at<=now<expires_at or now-signed_at>self.max_age_seconds: raise ApprovalTransportError("approval is stale, expired, or not yet valid")
        signature=evidence.get("signature")
        try: raw=base64.b64decode(signature,validate=True)
        except Exception as error: raise ApprovalTransportError("approval signature encoding is invalid") from error
        body={field:evidence[field] for field in FIELDS}; InvalidSignature,_,_,_=_crypto()
        try: key["public_key"].verify(raw,_canonical(body))
        except InvalidSignature as error: raise ApprovalTransportError("approval signature is invalid") from error
        return {"actor":evidence["actor"],"assurance":assurance,"evidence_id":evidence["evidence_id"]}


class SignedApprovalBridge:
    """Host-only adapter from verified public-key evidence to internal approval ingestion."""
    def __init__(self,roster: Ed25519ApprovalRoster,backend: Any):
        self.roster=roster; self.backend=backend

    def approve(self,evidence: Mapping[str,Any]) -> dict:
        request_id=evidence.get("request_id") if isinstance(evidence,Mapping) else None
        if not isinstance(request_id,str) or not request_id: raise ApprovalTransportError("signed approval request_id is invalid")
        try: request=self.backend.get_request(request_id)
        except Exception as error: raise ApprovalTransportError("signed approval request is unavailable") from error
        verified=self.roster.verify(evidence,request)
        signature=base64.b64decode(evidence["signature"],validate=True)
        provenance={"transport":"ed25519","key_id":evidence["key_id"],"signed_at":evidence["signed_at"],"signature_sha256":hashlib.sha256(signature).hexdigest()}
        return self.backend.approve_request(request_id,actor=verified["actor"],assurance=verified["assurance"],evidence_id=verified["evidence_id"],provenance=provenance,expires_at=evidence["expires_at"])


def main(argv: list[str]|None=None) -> int:
    parser=argparse.ArgumentParser(description="Sign an exact Semantic Gate human approval decision")
    parser.add_argument("--decision",required=True,help="Path to exact unsigned decision JSON")
    parser.add_argument("--private-key",required=True,help="Path to Ed25519 PKCS8 PEM; never pass key material directly")
    parser.add_argument("--output",default="-",help="Output path or - for stdout")
    args=parser.parse_args(argv)
    try: decision=json.loads(Path(args.decision).read_text()); signed=sign_approval(decision,args.private_key)
    except (OSError,json.JSONDecodeError,ApprovalTransportError) as error: parser.error(str(error))
    encoded=json.dumps(signed,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n"
    if args.output=="-": print(encoded,end="")
    else: Path(args.output).write_text(encoded)
    return 0


if __name__=="__main__": raise SystemExit(main())
