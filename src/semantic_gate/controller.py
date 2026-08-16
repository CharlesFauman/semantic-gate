#!/usr/bin/env python3
"""Transport-independent policy controller around Semantic Gate."""
from __future__ import annotations
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

    def __init__(self, backend: Any, ledger: Ledger, *, clock):
        self.backend = backend
        self.ledger = ledger
        self.clock = clock

    def _allowed(self, principal: str, action: str):
        controls = self.ledger.controls()
        if controls["pause_all"] is True:
            raise GateControlError("all actions are paused")
        if principal in controls["revoked_principals"]:
            raise GateControlError("principal is revoked")
        domain = action.split(".", 1)[0]
        if domain in controls["paused_domains"]:
            raise GateControlError(f"action domain is paused: {domain}")

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
        self.ledger.record_request(request, event="requested", actor=principal)
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
        if request["state"] in {"blocked", "cancelled", "simulated", "executed", "failed", "expired", "denied"}:
            return request
        live = self.backend.get_request(request_id, requester=None if admin else principal)
        live["updated_at"] = request.get("updated_at", request["created_at"])
        live.pop("trusted_context", None)
        return live

    def list_requests(self, *, principal: str, admin: bool = False, limit: int = 100):
        requests = self.ledger.list_requests(limit=limit)
        return requests if admin else [item for item in requests if item["requester"] == principal]

    def cancel(self, request_id: str, *, principal: str):
        request = self.backend.cancel_request(request_id, requester=principal)
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
        self.ledger.record_request(request, event="approved", actor=actor)
        return request

    def deny(self, request_id: str, *, actor: str, actor_role: str):
        if actor_role != "admin":
            raise GateControlError("admin denial transport is required")
        prior = self.ledger.get_request(request_id)
        if prior is None:
            raise GateControlError("request not found")
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
