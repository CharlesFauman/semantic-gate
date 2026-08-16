#!/usr/bin/env python3
"""Transport-independent policy controller around Semantic Gate."""
from __future__ import annotations

from typing import Any, Mapping

from .storage import Ledger


class GateControlError(ValueError):
    pass


class GateControl:
    REQUEST_FIELDS = {"action", "parameters", "context", "idempotency_key"}

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
        unknown = set(payload) - GateControl.REQUEST_FIELDS
        missing = GateControl.REQUEST_FIELDS - set(payload)
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
        return dict(payload)

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
        )
        request["updated_at"] = int(self.clock())
        request.pop("trusted_context", None)
        self.ledger.record_request(request, event="requested", actor=principal)
        return request

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

    def approve(self, request_id: str, *, actor: str, actor_role: str):
        if actor_role != "admin":
            raise GateControlError("admin approval transport is required")
        request = self.backend.approve_request(request_id, actor=actor)
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
