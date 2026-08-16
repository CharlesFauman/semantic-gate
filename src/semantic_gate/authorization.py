#!/usr/bin/env python3
"""Signed deferred authorizations and crash-aware single-use broker consumption."""
from __future__ import annotations

import hashlib
import hmac
import base64
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Mapping


class AuthorizationError(ValueError):
    pass


class UnknownOutcomeError(RuntimeError):
    """Target may have accepted the effect, but no definitive result was received."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")
    except (TypeError,ValueError,OverflowError,RecursionError) as error:
        raise AuthorizationError("authorization must contain strict JSON") from error


CLAIMS={
    "authorization_id","issuer","audience","request_id","request_hash","requester","assurance","action","target",
    "parameters","parameters_hash","policy_hash","approval_evidence_ids","approval_provenance","issued_at","expires_at",
    "nonce","execution_enabled","simulation_only",
}
TOKEN=CLAIMS|{"signature"}


class HMACAuthorizationAuthority:
    """Host-owned signer for exact, expiring authorization claims."""
    def __init__(self,key: bytes,*,issuer: str):
        if not isinstance(key,(bytes,bytearray)) or len(key)<32: raise ValueError("authorization key must contain at least 32 bytes")
        if not isinstance(issuer,str) or not issuer: raise ValueError("authorization issuer must be non-empty")
        self.key=bytes(key); self.issuer=issuer

    def issue(self,claims: Mapping[str,Any]) -> dict:
        if not isinstance(claims,Mapping) or set(claims)!=CLAIMS: raise AuthorizationError("authorization claims are malformed")
        body=json.loads(_canonical(claims)); body["issuer"]=self.issuer
        parameters=body.get("parameters")
        if not isinstance(parameters,dict): raise AuthorizationError("authorization parameters must be an object")
        body["parameters_hash"]=hashlib.sha256(_canonical(parameters)).hexdigest()
        self._validate_body(body)
        body["signature"]=hmac.new(self.key,_canonical(body),hashlib.sha256).hexdigest()
        return body

    def verify(self,token: Mapping[str,Any],*,audience: str,now: int) -> dict:
        if not isinstance(token,Mapping) or set(token)!=TOKEN: raise AuthorizationError("authorization token is malformed")
        body={key:value for key,value in token.items() if key!="signature"}; self._validate_body(body)
        signature=token.get("signature")
        if not isinstance(signature,str) or not hmac.compare_digest(signature,hmac.new(self.key,_canonical(body),hashlib.sha256).hexdigest()): raise AuthorizationError("authorization signature is invalid")
        if body["issuer"]!=self.issuer or body["audience"]!=audience: raise AuthorizationError("authorization issuer or audience is invalid")
        if type(now) is not int or not (body["issued_at"]<=now<body["expires_at"]): raise AuthorizationError("authorization is expired or not yet valid")
        if hashlib.sha256(_canonical(body["parameters"])).hexdigest()!=body["parameters_hash"]: raise AuthorizationError("authorization parameters hash is invalid")
        return json.loads(_canonical(body))

    @staticmethod
    def _validate_body(body: Mapping[str,Any]) -> None:
        for field in ("authorization_id","issuer","audience","request_id","request_hash","requester","action","target","parameters_hash","policy_hash","nonce"):
            if not isinstance(body.get(field),str) or not body[field]: raise AuthorizationError(f"authorization {field} is invalid")
        if body.get("assurance") not in {"ask","step_up"}: raise AuthorizationError("authorization assurance is invalid")
        approvals=body.get("approval_evidence_ids")
        if not isinstance(approvals,list) or not approvals or any(not isinstance(item,str) or not item for item in approvals) or len(approvals)!=len(set(approvals)): raise AuthorizationError("authorization approval_evidence_ids are invalid")
        provenance=body.get("approval_provenance")
        if not isinstance(provenance,dict) or set(provenance)!=set(approvals) or any(not isinstance(value,dict) for value in provenance.values()): raise AuthorizationError("authorization approval_provenance is invalid")
        if type(body.get("issued_at")) is not int or type(body.get("expires_at")) is not int or body["expires_at"]<=body["issued_at"]: raise AuthorizationError("authorization time bounds are invalid")
        if type(body.get("execution_enabled")) is not bool or type(body.get("simulation_only")) is not bool: raise AuthorizationError("authorization execution flags are invalid")
        if not isinstance(body.get("parameters"),dict): raise AuthorizationError("authorization parameters must be an object")
        _canonical(body)


def _ed_crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
    except ImportError as error: raise AuthorizationError("install semantic-gate[approvals] for Ed25519 support") from error
    return InvalidSignature,serialization,Ed25519PrivateKey,Ed25519PublicKey


class Ed25519AuthorizationVerifier:
    """Public-key-only verifier suitable for a broker process."""
    def __init__(self,public_key,*,issuer: str):
        _,serialization,_,Ed25519PublicKey=_ed_crypto()
        if isinstance(public_key,Ed25519PublicKey): key=public_key
        elif isinstance(public_key,Path):
            try:
                text=public_key.read_bytes(); key=serialization.load_pem_public_key(text) if text.startswith(b"-----BEGIN") else Ed25519PublicKey.from_public_bytes(text)
            except Exception as error: raise AuthorizationError("Ed25519 authorization public key is invalid") from error
        elif isinstance(public_key,str):
            try: key=Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key,validate=True))
            except Exception as error: raise AuthorizationError("Ed25519 authorization public key is invalid") from error
        else: raise AuthorizationError("Ed25519 authorization public key is invalid")
        if not isinstance(issuer,str) or not issuer: raise AuthorizationError("authorization issuer must be non-empty")
        self.public_key=key; self.issuer=issuer

    def verify(self,token: Mapping[str,Any],*,audience: str,now: int) -> dict:
        if not isinstance(token,Mapping) or set(token)!=TOKEN: raise AuthorizationError("authorization token is malformed")
        body={key:value for key,value in token.items() if key!="signature"}; HMACAuthorizationAuthority._validate_body(body)
        if body["issuer"]!=self.issuer or body["audience"]!=audience: raise AuthorizationError("authorization issuer or audience is invalid")
        if type(now) is not int or not body["issued_at"]<=now<body["expires_at"]: raise AuthorizationError("authorization is expired or not yet valid")
        if hashlib.sha256(_canonical(body["parameters"])).hexdigest()!=body["parameters_hash"]: raise AuthorizationError("authorization parameters hash is invalid")
        try: signature=base64.b64decode(token["signature"],validate=True)
        except Exception as error: raise AuthorizationError("authorization signature encoding is invalid") from error
        InvalidSignature,_,_,_=_ed_crypto()
        try: self.public_key.verify(signature,_canonical(body))
        except InvalidSignature as error: raise AuthorizationError("authorization signature is invalid") from error
        return json.loads(_canonical(body))


class Ed25519AuthorizationAuthority:
    """Private signer; distribute only `verifier()` to brokers."""
    def __init__(self,private_key,*,issuer: str):
        _,serialization,Ed25519PrivateKey,_=_ed_crypto()
        if isinstance(private_key,Ed25519PrivateKey): key=private_key
        elif isinstance(private_key,(str,Path)):
            try: key=serialization.load_pem_private_key(Path(private_key).read_bytes(),password=None)
            except Exception as error: raise AuthorizationError("Ed25519 authorization private key is invalid") from error
        else: raise AuthorizationError("Ed25519 authorization private key is invalid")
        if not isinstance(key,Ed25519PrivateKey): raise AuthorizationError("authorization key is not Ed25519")
        if not isinstance(issuer,str) or not issuer: raise AuthorizationError("authorization issuer must be non-empty")
        self.private_key=key; self.issuer=issuer

    def issue(self,claims: Mapping[str,Any]) -> dict:
        if not isinstance(claims,Mapping) or set(claims)!=CLAIMS: raise AuthorizationError("authorization claims are malformed")
        body=json.loads(_canonical(claims)); body["issuer"]=self.issuer
        body["parameters_hash"]=hashlib.sha256(_canonical(body.get("parameters"))).hexdigest(); HMACAuthorizationAuthority._validate_body(body)
        body["signature"]=base64.b64encode(self.private_key.sign(_canonical(body))).decode("ascii"); return body

    def verifier(self) -> Ed25519AuthorizationVerifier:
        return Ed25519AuthorizationVerifier(self.private_key.public_key(),issuer=self.issuer)

    def verify(self,token: Mapping[str,Any],*,audience: str,now: int) -> dict:
        return self.verifier().verify(token,audience=audience,now=now)


class SQLiteAuthorizationStore:
    """Durable authorization lifecycle. `executing` becomes `unknown` after crash recovery."""
    def __init__(self,path: str|Path):
        self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True); self.lock=threading.RLock()
        self.db=sqlite3.connect(self.path,check_same_thread=False,isolation_level=None); self.db.row_factory=sqlite3.Row
        self.db.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;
        PRAGMA synchronous=FULL;
        PRAGMA busy_timeout=5000;
        CREATE TABLE IF NOT EXISTS authorizations(
          authorization_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, state TEXT NOT NULL,
          issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
          token_json TEXT NOT NULL, consumer TEXT, receipt_json TEXT, request_snapshot_json TEXT NOT NULL DEFAULT '{}'
        );
        """)
        columns={row[1] for row in self.db.execute("PRAGMA table_info(authorizations)")}
        if "request_snapshot_json" not in columns: self.db.execute("ALTER TABLE authorizations ADD COLUMN request_snapshot_json TEXT NOT NULL DEFAULT '{}'")

    def close(self):
        with self.lock:
            if self.db is not None: self.db.close(); self.db=None

    def _project_request_locked(self,request_id: str,authorization_id: str,state: str,*,receipt: Mapping[str,Any]|None,now: int) -> None:
        auth_row=self.db.execute("SELECT request_snapshot_json FROM authorizations WHERE authorization_id=?",(authorization_id,)).fetchone()
        request=json.loads(auth_row["request_snapshot_json"]) if auth_row and auth_row["request_snapshot_json"] else {}
        request_row=None
        if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='requests'").fetchone(): request_row=self.db.execute("SELECT snapshot_json FROM requests WHERE request_id=?",(request_id,)).fetchone()
        if request_row: request=json.loads(request_row["snapshot_json"])
        if not request: return
        authorization=dict(request.get("authorization") or {})
        if authorization.get("authorization_id")!=authorization_id: return
        public_state={"issued":"authorized","executing":"consuming","unknown":"outcome_unknown"}.get(state,state)
        authorization["status"]=state
        if receipt is not None: authorization["receipt"]=json.loads(_canonical(receipt))
        request["authorization"]=authorization; request["state"]=public_state; request["consumption_possible"]=state=="issued"; request["updated_at"]=int(now)
        encoded=_canonical(request).decode(); self.db.execute("UPDATE authorizations SET request_snapshot_json=? WHERE authorization_id=?",(encoded,authorization_id))
        if request_row:
            self.db.execute("UPDATE requests SET state=?,updated_at=?,snapshot_json=? WHERE request_id=?",(public_state,int(now),encoded,request_id))
            if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit'").fetchone(): self.db.execute("INSERT INTO audit(request_id,event,actor,at,metadata_json) VALUES(?,?,?,?,?)",(request_id,"authorization_"+state,"authorization-store",int(now),_canonical({"authorization_id":authorization_id}).decode()))

    def record_issued(self,token: Mapping[str,Any],request_snapshot: Mapping[str,Any]|None=None) -> dict:
        encoded=_canonical(token).decode(); authorization_id=token.get("authorization_id")
        if request_snapshot is None:
            request_snapshot={"request_id":token["request_id"],"request_hash":token["request_hash"],"action":token["action"],"requester":token["requester"],"state":"authorized","created_at":int(token["issued_at"]),"updated_at":int(token["issued_at"]),"parameters":json.loads(_canonical(token["parameters"])),"context":{},"gates":[],"execution_possible":False,"consumption_possible":True,"authorization":{"authorization_id":authorization_id,"audience":token["audience"],"action":token["action"],"target":token["target"],"parameters_hash":token["parameters_hash"],"issued_at":token["issued_at"],"expires_at":token["expires_at"],"status":"issued"}}
        snapshot=json.loads(_canonical(request_snapshot))
        if snapshot.get("request_id")!=token.get("request_id") or snapshot.get("state")!="authorized" or not isinstance(snapshot.get("authorization"),dict) or snapshot["authorization"].get("authorization_id")!=authorization_id: raise AuthorizationError("authorized request snapshot is inconsistent")
        snapshot_encoded=_canonical(snapshot).decode()
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row=self.db.execute("SELECT token_json,state,request_id,receipt_json,updated_at FROM authorizations WHERE authorization_id=?",(authorization_id,)).fetchone()
                if row and row["token_json"]!=encoded: raise AuthorizationError("conflicting authorization_id")
                if not row:
                    self.db.execute("INSERT INTO authorizations(authorization_id,request_id,state,issued_at,expires_at,updated_at,token_json,consumer,receipt_json,request_snapshot_json) VALUES(?,?,?,?,?,?,?,?,?,?)",(authorization_id,token["request_id"],"issued",int(token["issued_at"]),int(token["expires_at"]),int(token["issued_at"]),encoded,None,None,snapshot_encoded))
                    state="issued"; receipt=None
                else:
                    state=row["state"]; receipt=json.loads(row["receipt_json"]) if row["receipt_json"] else None
                if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='requests'").fetchone():
                    request_row=self.db.execute("SELECT 1 FROM requests WHERE request_id=?",(token["request_id"],)).fetchone()
                    if request_row and not row: self.db.execute("UPDATE requests SET state='authorized',updated_at=?,snapshot_json=? WHERE request_id=?",(int(token["issued_at"]),snapshot_encoded,token["request_id"]))
                self._project_request_locked(token["request_id"],str(authorization_id),state,receipt=receipt,now=int(row["updated_at"]) if row else int(token["issued_at"]))
                self.db.commit()
            except Exception: self.db.rollback(); raise
        return self.get(str(authorization_id))

    def get(self,authorization_id: str) -> dict|None:
        with self.lock: row=self.db.execute("SELECT * FROM authorizations WHERE authorization_id=?",(authorization_id,)).fetchone()
        if not row: return None
        return {"authorization_id":row["authorization_id"],"request_id":row["request_id"],"state":row["state"],"issued_at":row["issued_at"],"expires_at":row["expires_at"],"updated_at":row["updated_at"],"consumer":row["consumer"],"token":json.loads(row["token_json"]),"receipt":json.loads(row["receipt_json"]) if row["receipt_json"] else None,"request_snapshot":json.loads(row["request_snapshot_json"])}

    def get_for_request(self,request_id: str) -> dict|None:
        with self.lock: row=self.db.execute("SELECT authorization_id FROM authorizations WHERE request_id=? ORDER BY issued_at DESC,authorization_id DESC LIMIT 1",(request_id,)).fetchone()
        return self.get(row["authorization_id"]) if row else None

    def list_metadata(self,states: set[str]|None=None) -> list[dict]:
        allowed={"issued","executing","executed","failed","simulated","unknown","cancelled","expired"}
        if states is not None and (not states or states-allowed): raise AuthorizationError("authorization state filter is invalid")
        query="SELECT authorization_id,request_id,state,issued_at,expires_at,updated_at,consumer FROM authorizations"; args=[]
        if states:
            query+=" WHERE state IN ("+",".join("?" for _ in states)+")"; args=sorted(states)
        query+=" ORDER BY authorization_id"
        with self.lock: rows=self.db.execute(query,args).fetchall()
        return [dict(row) for row in rows]

    def revoke_all_issued(self,*,actor: str,now: int) -> int:
        if not isinstance(actor,str) or not actor: raise AuthorizationError("revocation actor is required")
        receipt={"actor":actor,"reason":"bulk_rollback_revocation"}; encoded=_canonical(receipt).decode()
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                rows=self.db.execute("SELECT authorization_id,request_id FROM authorizations WHERE state='issued' ORDER BY authorization_id").fetchall(); revoked=0
                for row in rows:
                    changed=self.db.execute("UPDATE authorizations SET state='cancelled',receipt_json=?,updated_at=? WHERE authorization_id=? AND state='issued'",(encoded,int(now),row["authorization_id"])).rowcount
                    if changed==1:
                        self._project_request_locked(row["request_id"],row["authorization_id"],"cancelled",receipt=receipt,now=int(now)); revoked+=1
                self.db.commit()
            except Exception:
                if self.db.in_transaction: self.db.rollback()
                raise
        return revoked

    def begin_consumption(self,authorization_id: str,*,consumer: str,now: int) -> dict:
        if not isinstance(consumer,str) or not consumer: raise AuthorizationError("consumer must be non-empty")
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row=self.db.execute("SELECT request_id,state,expires_at FROM authorizations WHERE authorization_id=?",(authorization_id,)).fetchone()
                if not row or row["state"]!="issued": raise AuthorizationError("authorization is not consumable")
                if int(now)>=row["expires_at"]:
                    self.db.execute("UPDATE authorizations SET state='expired',updated_at=? WHERE authorization_id=?",(int(now),authorization_id)); self._project_request_locked(row["request_id"],authorization_id,"expired",receipt=None,now=int(now)); self.db.commit(); raise AuthorizationError("authorization is expired")
                self.db.execute("UPDATE authorizations SET state='executing',consumer=?,updated_at=? WHERE authorization_id=? AND state='issued'",(consumer,int(now),authorization_id))
                self._project_request_locked(row["request_id"],authorization_id,"executing",receipt=None,now=int(now))
                self.db.commit()
            except AuthorizationError:
                if self.db.in_transaction: self.db.rollback()
                raise
            except Exception: self.db.rollback(); raise
        return self.get(authorization_id)

    def complete(self,authorization_id: str,*,outcome: str,receipt: Mapping[str,Any],now: int) -> dict:
        if outcome not in {"executed","failed","simulated"}: raise AuthorizationError("invalid completion outcome")
        encoded=_canonical(receipt).decode()
        with self.lock,self.db:
            row=self.db.execute("SELECT request_id FROM authorizations WHERE authorization_id=?",(authorization_id,)).fetchone()
            changed=self.db.execute("UPDATE authorizations SET state=?,receipt_json=?,updated_at=? WHERE authorization_id=? AND state='executing'",(outcome,encoded,int(now),authorization_id)).rowcount
            if changed!=1: raise AuthorizationError("authorization is not executing")
            self._project_request_locked(row["request_id"],authorization_id,outcome,receipt=receipt,now=int(now))
        return self.get(authorization_id)

    def cancel(self,authorization_id: str,*,now: int) -> dict:
        with self.lock,self.db:
            row=self.db.execute("SELECT request_id,state FROM authorizations WHERE authorization_id=?",(authorization_id,)).fetchone()
            if row and row["state"]=="cancelled":
                self._project_request_locked(row["request_id"],authorization_id,"cancelled",receipt=None,now=int(now)); return self.get(authorization_id)
            changed=self.db.execute("UPDATE authorizations SET state='cancelled',updated_at=? WHERE authorization_id=? AND state='issued'",(int(now),authorization_id)).rowcount
            if changed!=1: raise AuthorizationError("authorization is not cancellable")
            self._project_request_locked(row["request_id"],authorization_id,"cancelled",receipt=None,now=int(now))
        return self.get(authorization_id)

    def recover_interrupted(self,authorization_id: str,*,actor: str,now: int) -> dict:
        if not isinstance(actor,str) or not actor: raise AuthorizationError("recovery actor is required")
        evidence={"actor":actor,"reason":"operator_confirmed_abandoned_execution"}; encoded=_canonical(evidence).decode()
        with self.lock,self.db:
            row=self.db.execute("SELECT request_id FROM authorizations WHERE authorization_id=?",(authorization_id,)).fetchone()
            changed=self.db.execute("UPDATE authorizations SET state='unknown',receipt_json=?,updated_at=? WHERE authorization_id=? AND state='executing'",(encoded,int(now),authorization_id)).rowcount
            if changed!=1: raise AuthorizationError("authorization is not executing")
            self._project_request_locked(row["request_id"],authorization_id,"unknown",receipt=evidence,now=int(now))
        return self.get(authorization_id)

    def mark_unknown(self,authorization_id: str,*,receipt: Mapping[str,Any],now: int) -> dict:
        encoded=_canonical(receipt).decode()
        with self.lock,self.db:
            row=self.db.execute("SELECT request_id FROM authorizations WHERE authorization_id=?",(authorization_id,)).fetchone()
            changed=self.db.execute("UPDATE authorizations SET state='unknown',receipt_json=?,updated_at=? WHERE authorization_id=? AND state='executing'",(encoded,int(now),authorization_id)).rowcount
            if changed!=1: raise AuthorizationError("authorization is not executing")
            self._project_request_locked(row["request_id"],authorization_id,"unknown",receipt=receipt,now=int(now))
        return self.get(authorization_id)

    def reconcile(self,authorization_id: str,*,outcome: str,actor: str,receipt: Mapping[str,Any],now: int) -> dict:
        if outcome not in {"executed","failed"} or not isinstance(actor,str) or not actor: raise AuthorizationError("invalid reconciliation")
        evidence={"actor":actor,"outcome":outcome,"receipt":dict(receipt)}; encoded=_canonical(evidence).decode()
        with self.lock,self.db:
            row=self.db.execute("SELECT request_id FROM authorizations WHERE authorization_id=?",(authorization_id,)).fetchone()
            changed=self.db.execute("UPDATE authorizations SET state=?,receipt_json=?,updated_at=? WHERE authorization_id=? AND state='unknown'",(outcome,encoded,int(now),authorization_id)).rowcount
            if changed!=1: raise AuthorizationError("authorization is not awaiting reconciliation")
            self._project_request_locked(row["request_id"],authorization_id,outcome,receipt=evidence,now=int(now))
        return self.get(authorization_id)


class AuthorizationBroker:
    """Consumes host-stored authorization IDs against a fixed target registry."""
    def __init__(self,*,broker_id: str,authority: Any,store: SQLiteAuthorizationStore,execution_authority: Any,revocation_checker: Callable[[dict],bool],expected_policy_hash: str,clock: Callable[[],int],actions: Mapping[str,Mapping[str,Any]]):
        if not isinstance(broker_id,str) or not broker_id: raise ValueError("broker_id must be non-empty")
        if execution_authority is None or not isinstance(getattr(execution_authority,"issuer",None),str): raise ValueError("host execution authority is required")
        if not callable(revocation_checker): raise ValueError("revocation_checker is required")
        if not isinstance(expected_policy_hash,str) or len(expected_policy_hash)!=64 or any(character not in "0123456789abcdef" for character in expected_policy_hash): raise ValueError("expected_policy_hash must be a lowercase SHA-256 hex digest")
        self.broker_id=broker_id; self.authority=authority; self.store=store; self.execution_authority=execution_authority; self.revocation_checker=revocation_checker; self.expected_policy_hash=expected_policy_hash; self.clock=clock; self.actions={}
        for action,spec in actions.items():
            fields={"target","outcome","recheck","execute"}
            if not isinstance(action,str) or not isinstance(spec,Mapping) or set(spec)!=fields or not isinstance(spec["target"],str) or spec["outcome"] not in {"idempotent","reconcilable"} or not callable(spec["recheck"]) or not callable(spec["execute"]): raise ValueError("broker action registry is malformed")
            self.actions[action]=dict(spec)

    def _verify_active(self,token: Mapping[str,Any]) -> dict:
        claims=self.authority.verify(token,audience=self.broker_id,now=int(self.clock()))
        if claims["policy_hash"]!=self.expected_policy_hash: raise AuthorizationError("authorization policy hash is stale or unexpected")
        try: active=self.revocation_checker(json.loads(_canonical(claims)))
        except Exception as error: raise AuthorizationError("authorization revocation status is unavailable") from error
        if active is not True: raise AuthorizationError("authorization is revoked or inactive")
        return claims

    def consume_id(self,authorization_id: str,*,consumer: str) -> dict:
        if not isinstance(authorization_id,str) or not authorization_id: raise AuthorizationError("authorization_id must be non-empty")
        record=self.store.get(authorization_id)
        if record is None: raise AuthorizationError("authorization is unavailable")
        token=record["token"]
        claims=self._verify_active(token)
        if claims["authorization_id"]!=authorization_id: raise AuthorizationError("stored authorization ID is inconsistent")
        if consumer!=claims["requester"]: raise AuthorizationError("authorization belongs to a different requester")
        spec=self.actions.get(claims["action"])
        if spec is None or spec["target"]!=claims["target"]: raise AuthorizationError("authorization action or target is unavailable")
        self.store.begin_consumption(authorization_id,consumer=consumer,now=int(self.clock()))
        try:
            checked=spec["recheck"](json.loads(_canonical(claims["parameters"])))
            if not isinstance(checked,dict) or checked.get("eligible") is not True: raise AuthorizationError("broker recheck denied execution")
            claims=self._verify_active(token)
        except Exception as error:
            try: self.store.complete(authorization_id,outcome="failed",receipt={"error_type":type(error).__name__,"phase":"pre_dispatch"},now=int(self.clock()))
            except AuthorizationError: pass
            if isinstance(error,AuthorizationError): raise
            raise AuthorizationError(f"broker pre-dispatch check failed: {type(error).__name__}") from error
        if claims["simulation_only"] or not claims["execution_enabled"]:
            receipt={"authority":self.execution_authority.issuer,"recheck":checked,"target_called":False,"outcome_contract":spec["outcome"]}
            record=self.store.complete(authorization_id,outcome="simulated",receipt=receipt,now=int(self.clock()))
            return {"authorization_id":authorization_id,"request_id":claims["request_id"],"state":record["state"],"receipt":receipt}
        try:
            result=spec["execute"](json.loads(_canonical(claims["parameters"])))
            if not isinstance(result,dict): raise AuthorizationError("broker target result must be an object")
            receipt={"authority":self.execution_authority.issuer,"recheck":checked,"target_called":True,"outcome_contract":spec["outcome"],"result":result}
            record=self.store.complete(authorization_id,outcome="executed",receipt=receipt,now=int(self.clock()))
            return {"authorization_id":authorization_id,"request_id":claims["request_id"],"state":record["state"],"receipt":receipt}
        except Exception as error:
            receipt={"error_type":type(error).__name__,"phase":"post_dispatch","outcome_contract":spec["outcome"]}
            try: self.store.mark_unknown(authorization_id,receipt=receipt,now=int(self.clock()))
            except Exception: pass
            raise AuthorizationError("broker outcome is unknown; reconcile before any retry") from error
