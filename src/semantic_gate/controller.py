#!/usr/bin/env python3
"""Transport-independent policy controller around Semantic Gate."""
from __future__ import annotations
import hashlib
import json
import re

from typing import Any, Mapping

from .storage import Ledger


class GateControlError(ValueError):
    pass


class GateControl:
    REQUEST_REQUIRED_FIELDS = {"action", "parameters", "context", "idempotency_key"}
    REQUEST_OPTIONAL_FIELDS = {"minimum_control"}
    OBSERVATION_FIELDS = {"event_id","phase","operation","semantic_class","outcome","occurred_at","metadata"}
    OBSERVATION_METADATA_KEYS = {"surface","node","harness","duration_ms","status","error_type","dropped_events","toolset","version"}

    def __init__(self, backend: Any, ledger: Ledger, *, clock, authorization_store: Any | None = None):
        self.backend = backend
        self.ledger = ledger
        self.clock = clock
        self.authorization_store=authorization_store

    def _allowed(self, principal: str, action: str):
        controls = self.ledger.controls()
        if controls["pause_all"] is True:
            raise GateControlError("all actions are paused")
        if principal in controls["revoked_principals"]:
            raise GateControlError("principal is revoked")
        domain = action.split(".", 1)[0]
        if domain in controls["paused_domains"]:
            raise GateControlError(f"action domain is paused: {domain}")

    def _sync_authorization(self,request: dict) -> dict:
        authorization=request.get("authorization")
        getter=getattr(self.authorization_store,"get",None)
        if isinstance(authorization,dict) and callable(getter): record=getter(authorization.get("authorization_id"))
        else:
            by_request=getattr(self.authorization_store,"get_for_request",None)
            record=by_request(request["request_id"]) if callable(by_request) else None
        if not isinstance(record,dict): return request
        stored_snapshot=record.get("request_snapshot")
        if not isinstance(authorization,dict) and isinstance(stored_snapshot,dict):
            repaired=dict(stored_snapshot)
        else:
            state=record.get("state"); public_state={"issued":"authorized","executing":"consuming","unknown":"outcome_unknown"}.get(state,state)
            if not isinstance(public_state,str): return request
            if request.get("state")==public_state and authorization.get("status")==state: return request
            repaired=dict(request); repaired["authorization"]=dict(authorization); repaired["authorization"]["status"]=state
            if record.get("receipt") is not None: repaired["authorization"]["receipt"]=record["receipt"]
            repaired["state"]=public_state; repaired["consumption_possible"]=state=="issued"; repaired["updated_at"]=int(record.get("updated_at",self.clock()))
        if self.ledger.compare_and_swap_request(expected=request,replacement=repaired,event="authorization_projection_repaired",actor="authorization-store"): return repaired
        return self.ledger.get_request(request["request_id"]) or request

    @staticmethod
    def _payload(payload: Mapping[str, Any]) -> dict:
        if not isinstance(payload, Mapping):
            raise GateControlError("request payload must be an object")
        unknown = set(payload) - GateControl.REQUEST_REQUIRED_FIELDS - GateControl.REQUEST_OPTIONAL_FIELDS
        missing = GateControl.REQUEST_REQUIRED_FIELDS - set(payload)
        if unknown:
            raise GateControlError(f"unknown request field(s): {sorted(unknown)}")
        if missing:
            raise GateControlError(f"missing request field(s): {sorted(missing)}")
        if not isinstance(payload["action"], str) or not payload["action"]:
            raise GateControlError("action must be a non-empty string")
        if not isinstance(payload["parameters"], Mapping) or not isinstance(payload["context"], Mapping):
            raise GateControlError("parameters and context must be objects")
        if not isinstance(payload["idempotency_key"], str) or not payload["idempotency_key"]:
            raise GateControlError("idempotency_key must be a non-empty string")
        minimum_control=payload.get("minimum_control","policy")
        if not isinstance(minimum_control,str) or minimum_control not in {"policy","ask","step_up"}:
            raise GateControlError("minimum_control must be policy, ask, or step_up")
        return {**payload,"minimum_control":minimum_control}

    def list_actions(self, principal: str):
        return self.backend.list_actions(principal)

    def explain_action(self, action: str, principal: str):
        return self.backend.explain_action(action, principal)

    def request_action(self, *, principal: str, payload: Mapping[str, Any], host_context: Mapping[str, Any]):
        data = self._payload(payload)
        self._allowed(principal, data["action"])
        try:
            encoded=json.dumps({"request":data,"host_context":dict(host_context)},sort_keys=True,separators=(",",":"),allow_nan=False)
        except (TypeError,ValueError,OverflowError,RecursionError) as error:
            raise GateControlError("request and host context must be strict JSON") from error
        fingerprint=hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        try: existing_id=self.ledger.reserve_idempotency(principal=principal,idempotency_key=data["idempotency_key"],fingerprint=fingerprint,now=int(self.clock()))
        except ValueError as error: raise GateControlError(str(error)) from error
        if existing_id is not None:
            existing=self.ledger.get_request(existing_id)
            if existing is None: raise GateControlError("idempotency binding references a missing request")
            return existing
        request = self.backend.request_action(
            action=data["action"],
            parameters=dict(data["parameters"]),
            context=dict(data["context"]),
            trusted_context=dict(host_context),
            requester=principal,
            idempotency_key=data["idempotency_key"],
            minimum_control=data["minimum_control"],
        )
        request["updated_at"] = int(self.clock())
        request.pop("trusted_context", None)
        try: self.ledger.complete_reserved_request(request,principal=principal,idempotency_key=data["idempotency_key"],fingerprint=fingerprint,event="requested",actor=principal)
        except ValueError as error: raise GateControlError(str(error)) from error
        return request

    def observe(self, *, principal: str, payload: Mapping[str, Any]):
        if not isinstance(payload,Mapping):
            raise GateControlError("observation payload must be an object")
        unknown=set(payload)-self.OBSERVATION_FIELDS; missing=self.OBSERVATION_FIELDS-set(payload)
        if unknown: raise GateControlError(f"unknown observation field(s): {sorted(unknown)}")
        if missing: raise GateControlError(f"missing observation field(s): {sorted(missing)}")
        event_id=payload["event_id"]
        if not isinstance(event_id,str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}",event_id): raise GateControlError("event_id is invalid")
        if not isinstance(payload["phase"],str) or payload["phase"] not in {"attempted","completed"}: raise GateControlError("phase is invalid")
        if not isinstance(payload["outcome"],str) or payload["outcome"] not in {"started","succeeded","failed","cancelled","unknown"}: raise GateControlError("outcome is invalid")
        for key in ("operation","semantic_class"):
            if not isinstance(payload[key],str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,200}",payload[key]): raise GateControlError(f"{key} is invalid")
        if type(payload["occurred_at"]) is not int or payload["occurred_at"]<0: raise GateControlError("occurred_at is invalid")
        metadata=payload["metadata"]
        if not isinstance(metadata,Mapping) or len(metadata)>16: raise GateControlError("metadata must be a bounded object")
        for key,value in metadata.items():
            if key not in self.OBSERVATION_METADATA_KEYS: raise GateControlError(f"metadata key is not allowed: {key}")
            if type(value) not in {str,int,bool,type(None)} or isinstance(value,str) and not re.fullmatch(r"[A-Za-z0-9_.:/-]{0,128}",value) or type(value) is int and not 0<=value<=2**63-1:
                raise GateControlError("metadata values must be flat scalar labels")
        observation={key:payload[key] for key in self.OBSERVATION_FIELDS}
        observation["metadata"]=dict(metadata); observation["principal"]=principal; observation["received_at"]=int(self.clock())
        return self.ledger.record_observation(observation)

    def get_request(self, request_id: str, *, principal: str, admin: bool = False):
        request = self.ledger.get_request(request_id)
        if request is None:
            raise GateControlError("request not found")
        if not admin and request["requester"] != principal:
            raise GateControlError("principal cannot access this request")
        request=self._sync_authorization(request)
        if request["state"] in {"blocked", "cancelled", "simulated", "executed", "failed", "expired", "denied", "authorized", "consuming", "outcome_unknown"}:
            return request
        live = self.backend.get_request(request_id, requester=None if admin else principal)
        live["updated_at"] = request.get("updated_at", request["created_at"])
        live.pop("trusted_context", None)
        return live

    def list_requests(self, *, principal: str, admin: bool = False, limit: int = 100):
        requests = [self._sync_authorization(item) for item in self.ledger.list_requests(limit=limit)]
        return requests if admin else [item for item in requests if item["requester"] == principal]

    def cancel(self, request_id: str, *, principal: str):
        persisted=self.ledger.get_request(request_id)
        if persisted is not None and persisted.get("state")=="cancelled":
            if persisted["requester"]!=principal: raise GateControlError("only the original requester may cancel")
            return persisted
        if persisted is not None and persisted.get("state")=="authorized":
            if persisted["requester"]!=principal: raise GateControlError("only the original requester may cancel")
            if self.authorization_store is None: raise GateControlError("authorization store is unavailable")
            try: self.authorization_store.cancel(persisted["authorization"]["authorization_id"],now=int(self.clock()))
            except Exception as error: raise GateControlError(f"authorization cannot be revoked: {type(error).__name__}") from error
            persisted["state"]="cancelled"; persisted["authorization"]["status"]="cancelled"; persisted["consumption_possible"]=False; persisted["updated_at"]=int(self.clock())
            self.ledger.record_request(persisted,event="cancelled",actor=principal); return persisted
        try: request = self.backend.cancel_request(request_id, requester=principal)
        except Exception:
            if persisted is None or persisted.get("requester")!=principal or persisted.get("state") not in {"processing","waiting_for_approval"}: raise
            request=dict(persisted); request["state"]="cancelled"
        request["updated_at"] = int(self.clock())
        request.pop("trusted_context", None)
        self.ledger.record_request(request, event="cancelled", actor=principal)
        return request

    def approve(self, request_id: str, *, actor: str, actor_role: str, assurance: str = "ask"):
        if actor_role != "admin":
            raise GateControlError("admin approval transport is required")
        if assurance not in {"ask","step_up"}:
            raise GateControlError("approval assurance is invalid")
        request = self.backend.approve_request(request_id, actor=actor, assurance=assurance)
        request["updated_at"] = int(self.clock())
        request.pop("trusted_context", None)
        event="authorized" if request.get("state")=="authorized" else "approved"
        self.ledger.record_request(request, event=event, actor=actor)
        return request

    def deny(self, request_id: str, *, actor: str, actor_role: str):
        if actor_role != "admin":
            raise GateControlError("admin denial transport is required")
        prior = self.ledger.get_request(request_id)
        if prior is None:
            raise GateControlError("request not found")
        if prior.get("state")=="authorized":
            if self.authorization_store is None: raise GateControlError("authorization store is unavailable")
            try: self.authorization_store.cancel(prior["authorization"]["authorization_id"],now=int(self.clock()))
            except Exception as error: raise GateControlError(f"authorization cannot be revoked: {type(error).__name__}") from error
            request=dict(prior); request["authorization"]=dict(prior["authorization"]); request["authorization"]["status"]="cancelled"; request["consumption_possible"]=False
        else:
            try:
                request = self.backend.cancel_request(request_id, requester=prior["requester"])
            except Exception:
                request = dict(prior)
        request["state"] = "denied"
        request["updated_at"] = int(self.clock())
        self.ledger.record_request(request, event="denied", actor=actor)
        return request

    def set_control(self, key: str, value: Any, *, actor: str):
        self.ledger.set_control(key, value, actor=actor, now=int(self.clock()))
        return self.ledger.controls()
