#!/usr/bin/env python3
"""Build deterministic Semantic Gate workflows from a portable semantic action catalogue."""
from __future__ import annotations

from typing import Any, Mapping


def build_policy(catalog: Mapping[str, Any], principals: Mapping[str, Mapping[str, Any]]) -> dict:
    allowed_principals = sorted(
        principal_id for principal_id, config in principals.items()
        if config.get("enabled") is True and config.get("role") in {"agent", "service", "admin"}
    )
    if not allowed_principals:
        raise ValueError("at least one enabled principal is required")
    workflows = {}
    for action_id, action in sorted(catalog.get("actions", {}).items()):
        if action.get("effect") in {"read", "prohibited"} or action.get("approval") in {"none", "prohibited"}:
            continue
        risk = action.get("risk")
        step_up = risk == "R3" or action.get("approval") == "step_up"
        level = "human_step_up" if step_up else "human_approve_once"
        ttl = 300 if step_up else 600
        target = "semantic.action." + action_id
        workflows[action_id] = {
            "description": action.get("summary", action_id),
            "principals": allowed_principals,
            "target_tool": target,
            "parameter_schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["summary", "target", "details"],
                "properties": {
                    "summary": {"type": "string", "minLength": 1},
                    "target": {"type": "string", "minLength": 1},
                    "details": {"type": "object"},
                },
            },
            "gates": [
                {"id":"schema","kind":"schema","requires":[]},
                {
                    "id":"precheck","kind":"tool","requires":["schema"],
                    "tool":"semantic.policy_precheck",
                    "input":{"action":"$action","parameters":"$parameters"},
                    "expect":{"path":"eligible","op":"eq","value":True},
                    "recheck":False,
                },
                {
                    "id":"notify","kind":"notify","requires":["precheck"],
                    "recipient":"human_owner",
                    "template":f"Review {action_id}",
                },
                {
                    "id":"approval","kind":"approval","requires":["notify"],
                    "level":level,"ttl_seconds":ttl,
                },
                {
                    "id":"recheck","kind":"tool","requires":["approval"],
                    "tool":"semantic.policy_precheck",
                    "input":{"action":"$action","parameters":"$parameters"},
                    "expect":{"path":"eligible","op":"eq","value":True},
                    "recheck":True,
                },
                {
                    "id":"execute","kind":"execute","requires":["recheck"],
                    "tool":target,"simulation_only":True,
                },
            ],
        }
    return {"version":1,"mode":"simulation_only","execution_enabled":False,"workflows":workflows}
