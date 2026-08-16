#!/usr/bin/env python3
"""Language-neutral HTTP proposal example using the Python standard library."""
import json
import os
from urllib import request

payload={
    "action":"calendar.create_event",
    "parameters":{"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
    "context":{"surface":"example-http"},
    "idempotency_key":"example-http-calendar-1",
    "minimum_control":"policy",
}
req=request.Request(
    os.environ["SEMANTIC_GATE_URL"].rstrip("/")+"/api/v1/requests",
    data=json.dumps(payload,separators=(",",":")).encode(),
    headers={"Authorization":"Bearer "+os.environ["SEMANTIC_GATE_TOKEN"],"Content-Type":"application/json"},
    method="POST",
)
with request.urlopen(req,timeout=10) as response:
    result=json.load(response)
print({key:result[key] for key in ("request_id","state","policy_control","effective_control")})
