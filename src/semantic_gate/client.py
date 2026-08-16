#!/usr/bin/env python3
"""Small dependency-free direct HTTP client for Semantic Gate."""
from __future__ import annotations

import json
from urllib import error, request


class SemanticGateClientError(RuntimeError):
    pass


class SemanticGateClient:
    def __init__(self, base_url: str, capability_token: str, *, timeout: int = 30):
        self.base_url=base_url.rstrip("/"); self.token=capability_token; self.timeout=timeout

    def _call(self, method: str, path: str, payload=None):
        body=None if payload is None else json.dumps(payload,separators=(",", ":"),allow_nan=False).encode()
        headers={"Authorization":f"Bearer {self.token}","Accept":"application/json","User-Agent":"semantic-gate-python/0.2"}
        if body is not None: headers["Content-Type"]="application/json"
        req=request.Request(self.base_url+path,data=body,headers=headers,method=method)
        try:
            with request.urlopen(req,timeout=self.timeout) as response:
                return json.load(response)
        except error.HTTPError as exc:
            detail=exc.read(2048).decode(errors="replace")
            raise SemanticGateClientError(f"Semantic Gate HTTP {exc.code}: {detail}") from exc

    def list_actions(self): return self._call("GET","/api/v1/actions")
    def list_requests(self): return self._call("GET","/api/v1/requests")
    def get_request(self,request_id: str): return self._call("GET",f"/api/v1/requests/{request_id}")
    def request_action(self,action: str,*,parameters: dict,context: dict,idempotency_key: str):
        return self._call("POST","/api/v1/requests",{"action":action,"parameters":parameters,"context":context,"idempotency_key":idempotency_key})
    def observe_permission(self,*,event_id: str,phase: str,operation: str,semantic_class: str,outcome: str,occurred_at: int,metadata: dict):
        return self._call("POST","/api/v1/audit-observations",{"event_id":event_id,"phase":phase,"operation":operation,"semantic_class":semantic_class,"outcome":outcome,"occurred_at":occurred_at,"metadata":metadata})
    def cancel_request(self,request_id: str): return self._call("POST",f"/api/v1/requests/{request_id}/cancel",{})
