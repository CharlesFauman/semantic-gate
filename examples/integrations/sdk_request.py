#!/usr/bin/env python3
"""Proposal-only SDK example. Values come from the deployment environment."""
import os
from semantic_gate.client import SemanticGateClient

client=SemanticGateClient(os.environ["SEMANTIC_GATE_URL"],os.environ["SEMANTIC_GATE_TOKEN"])
request=client.request_action(
    "calendar.create_event",
    parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
    context={"surface":"example-sdk"},
    idempotency_key="example-sdk-calendar-1",
    minimum_control="step_up",
)
print({key:request[key] for key in ("request_id","state","policy_control","minimum_control","effective_control")})
