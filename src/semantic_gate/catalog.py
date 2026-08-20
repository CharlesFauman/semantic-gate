#!/usr/bin/env python3
"""Build deterministic Semantic Gate workflows from a portable semantic action catalogue.

Every catalogue entry must declare exactly one member of the closed four-way
``gate_class`` vocabulary. The gate class is the only classification input for
policy-owned auto-approval: action names and caller parameters never widen or
narrow it.
"""
from __future__ import annotations

from typing import Any, Mapping

# Closed, exhaustive classification vocabulary owned by the checked-in catalogue.
GATE_CLASSES: tuple[str, ...] = ("automatic", "human_communication", "human_spending", "prohibited")
# The only classes that keep the ordinary human gate for requestable actions:
# communication/sending/disclosure to a person or external recipient, and
# spending/transferring/purchasing/committing money.
HUMAN_GATE_CLASSES: tuple[str, ...] = ("human_communication", "human_spending")


def action_gate_class(entry: Any) -> str | None:
    """Return the declared gate class of one catalogue entry, or None if invalid."""
    if not isinstance(entry, Mapping):
        return None
    declared = entry.get("gate_class")
    return declared if isinstance(declared, str) and declared in GATE_CLASSES else None


def validate_catalog(catalog: Any) -> Mapping[str, Any]:
    """Validate that every catalogue entry declares exactly one consistent gate class."""
    if not isinstance(catalog, Mapping) or not isinstance(catalog.get("actions"), Mapping):
        raise ValueError("catalogue must be an object with an actions object")
    for action_id, entry in catalog["actions"].items():
        if not isinstance(action_id, str) or not action_id:
            raise ValueError("catalogue action identifiers must be non-empty strings")
        if not isinstance(entry, Mapping):
            raise ValueError(f"catalogue entry {action_id} must be an object")
        declared = action_gate_class(entry)
        if declared is None:
            raise ValueError(
                f"catalogue entry {action_id} must declare exactly one gate_class from {sorted(GATE_CLASSES)}"
            )
        marked_prohibited = entry.get("effect") == "prohibited" or entry.get("approval") == "prohibited"
        if marked_prohibited and declared != "prohibited":
            raise ValueError(f"catalogue entry {action_id} is marked prohibited but declares gate_class {declared}")
        if declared == "prohibited" and not marked_prohibited:
            raise ValueError(f"catalogue entry {action_id} declares gate_class prohibited without a prohibited effect/approval")
    return catalog


def build_policy(catalog: Mapping[str, Any], principals: Mapping[str, Mapping[str, Any]]) -> dict:
    validate_catalog(catalog)
    allowed_principals = sorted(
        principal_id for principal_id, config in principals.items()
        if config.get("enabled") is True and config.get("role") in {"agent", "service", "admin"}
    )
    if not allowed_principals:
        raise ValueError("at least one enabled principal is required")
    workflows = {}
    for action_id, action in sorted(catalog.get("actions", {}).items()):
        if action_gate_class(action) == "prohibited":
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
