#!/usr/bin/env python3
"""Content-free observer example. It has no proposal or approval authority."""
import os
import time
from semantic_gate.client import SemanticGateClient

client=SemanticGateClient(os.environ["SEMANTIC_GATE_URL"],os.environ["SEMANTIC_GATE_OBSERVER_TOKEN"])
result=client.observe_permission(
    event_id="example-observer:completed:0001",
    phase="completed",
    operation="document.export_pdf",
    semantic_class="document.write",
    outcome="succeeded",
    occurred_at=int(time.time()),
    metadata={"surface":"example","node":"example-node","harness":"observer"},
)
print({key:result[key] for key in ("event_id","principal","phase","operation","outcome")})
