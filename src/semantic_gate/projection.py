#!/usr/bin/env python3
"""Bounded decision-card projection for out-of-band human review notices.

A decision card is the only content a notifier should project into a chat,
mail or push surface. Every value comes from a closed, action-schema-owned
presentation contract or from host-authenticated request identity; agent-supplied
parameters, prompts, commands, paths, message bodies and credentials are never
projected. Values are deterministically sanitized, length-bounded and escaped.
"""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any, Mapping

CARD_TEXT_LIMIT = 160
WITHHELD = "withheld - review in the authenticated panel"
NOT_DECLARED = "not declared - treat as possible"
UNDECLARED = "not declared"
PANEL_REFERENCE = "the authenticated Semantic Gate panel"

# Closed presentation contract. A catalogue key outside this set is never projected.
PRESENTATION_FIELDS = frozenset({
    "proposed_effect", "reason", "node", "safe_target_field", "safe_target_values",
    "spends", "communicates", "changes_state",
})

CHALLENGE_FIELDS = frozenset({"request_id", "request_hash", "approval_gate_id", "expires_at"})

_ALLOWED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,:;!?()[]/@#+_'\"%$*=-"
)
_SLUG = re.compile(r"[A-Za-z0-9_.:@/-]{1,128}\Z")
_LABEL = re.compile(r"[A-Za-z0-9_.:/-]{1,128}\Z")
_RISK = re.compile(r"R[0-9]\Z")
_FINGERPRINT = re.compile(r"[0-9A-Za-z]{16,128}\Z")
_CONTROLS = frozenset({"policy", "ask", "step_up"})

_DELIVERY_MESSAGES = {
    "none": "No durable notification record; delivery is not yet proven.",
    "pending": "Notification queued; will retry after provider recovery.",
    "delivered": "Notification delivered.",
    "unknown": "Notification outcome unknown; automatic retry stopped to prevent duplicates.",
}
_DELIVERY_RANK = {"delivered": 0, "none": 1, "pending": 2, "unknown": 3}


def _bounded(value: Any, limit: int = CARD_TEXT_LIMIT) -> str | None:
    """Drop disallowed characters, collapse whitespace and bound the length."""
    if not isinstance(value, str):
        return None
    kept = "".join(character if character in _ALLOWED else " " if character.isspace() else "" for character in value)
    collapsed = " ".join(kept.split())
    if not collapsed:
        return None
    return collapsed if len(collapsed) <= limit else collapsed[:limit - 3].rstrip() + "..."


def _slug(value: Any) -> str | None:
    return value if isinstance(value, str) and _SLUG.fullmatch(value) else None


def _flag(value: Any) -> str:
    return "yes" if value is True else "no" if value is False else NOT_DECLARED


def _utc(value: Any) -> str:
    if type(value) is not int:
        return UNDECLARED
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def expiry_phrase(seconds: int | None) -> str:
    if seconds is None:
        return "unknown"
    if seconds <= 0:
        return "expired"
    if seconds < 60:
        return f"in {seconds} s"
    if seconds < 3600:
        return f"in {seconds // 60} min"
    return f"in {seconds // 3600} h {seconds % 3600 // 60} min"


def urgency(seconds: int | None) -> str:
    if seconds is None:
        return "unknown"
    if seconds <= 0:
        return "expired"
    if seconds <= 300:
        return "urgent"
    if seconds <= 3600:
        return "soon"
    return "scheduled"


def summarize_delivery(notices: Any) -> dict:
    """Reduce durable outbox rows to a bounded, content-free delivery summary."""
    states, identifiers, attempts = [], [], 0
    for notice in notices or ():
        if not isinstance(notice, Mapping):
            continue
        if notice.get("state") in _DELIVERY_RANK:
            states.append(str(notice["state"]))
        identifier = _slug(notice.get("notification_id"))
        if identifier:
            identifiers.append(identifier)
        if type(notice.get("attempts")) is int and notice["attempts"] > attempts:
            attempts = int(notice["attempts"])
    state = max(states, key=lambda item: _DELIVERY_RANK[item]) if states else "none"
    return {"state": state, "message": _DELIVERY_MESSAGES[state], "notification_ids": identifiers[:5], "attempts": attempts}


def _presentation(catalog: Any, action: Any) -> tuple[Mapping[str, Any], dict]:
    actions = catalog.get("actions") if isinstance(catalog, Mapping) else None
    entry = actions.get(action) if isinstance(actions, Mapping) and isinstance(action, str) else None
    entry = entry if isinstance(entry, Mapping) else {}
    declared = entry.get("presentation")
    declared = declared if isinstance(declared, Mapping) else {}
    return entry, {key: value for key, value in declared.items() if key in PRESENTATION_FIELDS}


def _safe_target(request: Mapping[str, Any], presentation: Mapping[str, Any]) -> str:
    field = presentation.get("safe_target_field")
    allowed = presentation.get("safe_target_values")
    parameters = request.get("parameters")
    if not isinstance(field, str) or not isinstance(allowed, (list, tuple)) or not isinstance(parameters, Mapping):
        return WITHHELD
    value = parameters.get(field)
    if not isinstance(value, str) or value not in [item for item in allowed if isinstance(item, str)]:
        return WITHHELD
    return _bounded(value) or WITHHELD


def _reaction_binding(request: Mapping[str, Any], now: int) -> dict | None:
    """Return the exact immutable challenge a reaction transport must submit, or None."""
    challenge = request.get("approval_challenge")
    if not isinstance(challenge, Mapping) or set(challenge) != set(CHALLENGE_FIELDS):
        return None
    if challenge.get("request_id") != request.get("request_id") or challenge.get("request_hash") != request.get("request_hash"):
        return None
    if type(challenge.get("expires_at")) is not int or challenge["expires_at"] <= now:
        return None
    return {field: challenge[field] for field in ("request_id", "request_hash", "approval_gate_id", "expires_at")}


def build_decision_card(request: Mapping[str, Any], *, catalog: Any, now: int, panel_reference: str | None = None, delivery: Any = None) -> dict:
    """Project one waiting request into a bounded, allowlisted decision card."""
    if not isinstance(request, Mapping):
        raise ValueError("request snapshot must be a mapping")
    entry, presentation = _presentation(catalog, request.get("action"))
    challenge = request.get("approval_challenge")
    expires_at = challenge.get("expires_at") if isinstance(challenge, Mapping) else None
    expires_at = expires_at if type(expires_at) is int else None
    remaining = expires_at - int(now) if expires_at is not None else None
    binding = _reaction_binding(request, int(now))
    fingerprint = str(request.get("request_hash", ""))
    fingerprint = fingerprint[:12] if _FINGERPRINT.fullmatch(fingerprint) else "unknown"
    control = lambda key: str(request.get(key)) if request.get(key) in _CONTROLS else UNDECLARED  # noqa: E731
    summary = summarize_delivery(delivery)
    return {
        "action": _slug(request.get("action")) or UNDECLARED,
        "proposed_effect": _bounded(presentation.get("proposed_effect")) or _bounded(entry.get("summary")) or WITHHELD,
        "safe_target": _safe_target(request, presentation),
        "reason": _bounded(presentation.get("reason")) or WITHHELD,
        "requester": _slug(request.get("requester")) or UNDECLARED,
        "node": _slug(presentation.get("node")) or UNDECLARED,
        "risk": str(entry.get("risk")) if isinstance(entry.get("risk"), str) and _RISK.fullmatch(entry["risk"]) else UNDECLARED,
        "policy_control": control("policy_control"),
        "caller_floor": control("minimum_control"),
        "effective_control": control("effective_control"),
        "spends_money": _flag(presentation.get("spends")),
        "communicates_externally": _flag(presentation.get("communicates")),
        "changes_state": _flag(presentation.get("changes_state")),
        "expires_at": expires_at,
        "expires_at_utc": _utc(expires_at),
        "expires_in_seconds": remaining,
        "expiry_phrase": expiry_phrase(remaining),
        "urgency": urgency(remaining),
        "approve_consequence": f"Approve authorizes exactly this request ({fingerprint}) once; it is not a standing permission.",
        "deny_consequence": "Deny ends this request; the agent must submit a new proposal to try again.",
        "request_id": _slug(request.get("request_id")) or UNDECLARED,
        "request_hash_fingerprint": fingerprint,
        "panel_reference": _bounded(panel_reference) or PANEL_REFERENCE,
        "delivery_state": summary["state"],
        "delivery_message": summary["message"],
        "notification_ids": summary["notification_ids"],
        "delivery_attempts": summary["attempts"],
        "decision_available": binding is not None,
        "reaction_binding": binding,
    }


def _facts(card: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    return (
        ("Proposed effect", card["proposed_effect"]),
        ("Safe target", card["safe_target"]),
        ("Reason", card["reason"]),
        ("Requester", card["requester"]),
        ("Node", card["node"]),
        ("Risk", card["risk"]),
        ("Policy control", card["policy_control"]),
        ("Caller floor", card["caller_floor"]),
        ("Effective control", card["effective_control"]),
        ("Can spend money", card["spends_money"]),
        ("Can communicate externally", card["communicates_externally"]),
        ("Changes state", card["changes_state"]),
        ("Request ID", card["request_id"]),
        ("Request fingerprint", card["request_hash_fingerprint"]),
    )


def render_decision_card_html(card: Mapping[str, Any]) -> str:
    """Render the card as an escaped HTML fragment for the authenticated panel."""
    rows = "".join(f"<dt>{html.escape(label)}</dt><dd>{html.escape(str(value))}</dd>" for label, value in _facts(card))
    identifiers = "".join(f" <code>{html.escape(identifier)}</code>" for identifier in card["notification_ids"])
    return (
        f"<h3>{html.escape(card['action'])}</h3>"
        f"<p class='chip {html.escape(card['urgency'])}'>Expires {html.escape(card['expiry_phrase'])}"
        f" · {html.escape(card['expires_at_utc'])}</p>"
        f"<dl class=facts>{rows}</dl>"
        f"<p><b>{html.escape(card['delivery_message'])}</b>{identifiers} · attempts {int(card['delivery_attempts'])}</p>"
        f"<p class=consequence><b>Approve once</b> {html.escape(card['approve_consequence'])}</p>"
        f"<p class=consequence><b>Deny</b> {html.escape(card['deny_consequence'])}</p>"
    )


def render_decision_card_text(card: Mapping[str, Any]) -> str:
    """Render the card as a compact plain-text notice for a chat or mail transport."""
    lines = [
        "Semantic Gate needs one decision.",
        f"Action: {card['action']}",
        f"Proposed effect: {card['proposed_effect']}",
        f"Safe target: {card['safe_target']}",
        f"Reason: {card['reason']}",
        f"Requester: {card['requester']} (node {card['node']})",
        f"Risk: {card['risk']} · effective control: {card['effective_control']}"
        f" (policy {card['policy_control']}, caller floor {card['caller_floor']})",
        f"Can spend money: {card['spends_money']} · Can communicate externally: {card['communicates_externally']}"
        f" · Changes state: {card['changes_state']}",
        f"Expires: {card['expiry_phrase']} ({card['expires_at_utc']})",
        f"Delivery: {card['delivery_message']}",
        f"Approve once: {card['approve_consequence']}",
        f"Deny: {card['deny_consequence']}",
        f"Request: {card['request_id']} · fingerprint {card['request_hash_fingerprint']}",
        "Decision: available for this exact request" if card["decision_available"]
        else "Decision: unavailable - the exact challenge is missing, changed or expired",
        f"Decide in: {card['panel_reference']}",
    ]
    return "\n".join(lines)


def decision_card_audit_labels(card: Mapping[str, Any]) -> dict:
    """Content-free labels suitable for the bounded audit-observation lane."""
    node = card["node"] if _LABEL.fullmatch(str(card["node"])) else "unknown"
    return {"surface": "decision-card", "node": node, "status": card["delivery_state"], "version": "1"}


# --- feed projection -----------------------------------------------------------------
# Three separate feeds. An ordinary tool outcome (nonzero exit, timeout, interrupt,
# cancellation) is execution telemetry, never a Semantic Gate decision or failure.
_OBSERVATION_LABELS = {
    "succeeded": "tool succeeded",
    "started": "tool started",
    "cancelled": "tool cancelled by its caller",
    "unknown": "tool outcome unknown",
}
_ERROR_LABELS = {
    "timeout": "tool timed out",
    "interrupted": "tool interrupted",
    "cancelled": "tool cancelled by its caller",
    "nonzero_exit": "tool exited with a nonzero exit status",
}
_AUDIT_LANES = {
    "requested": ("decisions", "decision requested"),
    "approved": ("decisions", "approved once by a human"),
    "auto_approved": ("decisions", "auto-approved by policy rule"),
    "denied": ("denials", "denied by a human decision"),
    "blocked": ("denials", "blocked by a policy precondition"),
    "expired": ("withdrawn", "expired without a decision"),
    "cancelled": ("withdrawn", "cancelled by the requester"),
    "failed": ("gate_errors", "gate or target error"),
    "control_changed": ("service", "control plane change"),
}
_LANE_SOURCES = {
    "decisions": "policy gate", "denials": "policy gate", "gate_errors": "policy gate",
    "withdrawn": "requester", "service": "coordinator control",
}


def classify_observation(row: Any) -> dict:
    """Label one audit observation as execution telemetry with a safe bounded reason."""
    if not isinstance(row, Mapping):
        raise ValueError("observation row must be a mapping")
    metadata = row.get("metadata") if isinstance(row.get("metadata"), Mapping) else {}
    error_type = metadata.get("error_type")
    outcome = row.get("outcome")
    label = _ERROR_LABELS.get(error_type if isinstance(error_type, str) else "")
    if label is None:
        label = _OBSERVATION_LABELS.get(outcome if isinstance(outcome, str) else "", "tool reported an outcome")
    return {
        "category": "execution_telemetry",
        "source": "tool telemetry",
        "is_gate_failure": False,
        "is_policy_denial": False,
        "label": label,
        "operation": _slug(row.get("operation")) or UNDECLARED,
        "semantic_class": _slug(row.get("semantic_class")) or UNDECLARED,
        "outcome": _slug(outcome) or UNDECLARED,
        "principal": _slug(row.get("principal")) or UNDECLARED,
        "correlation_id": _slug(row.get("correlation_id")),
        "event_id": _slug(row.get("event_id")) or UNDECLARED,
        "occurred_at": row.get("occurred_at") if type(row.get("occurred_at")) is int else None,
    }


def collapse_observations(rows: Any) -> list[dict]:
    """Collapse root and detail observations that share a correlation identity."""
    collapsed: dict[str, dict] = {}
    order: list[str] = []
    for row in rows or ():
        classified = classify_observation(row)
        key = classified["correlation_id"] or f"event:{classified['event_id']}"
        existing = collapsed.get(key)
        if existing is None:
            classified["occurrences"] = 1
            classified["event_ids"] = [classified["event_id"]]
            classified["first_seen_at"] = classified["occurred_at"]
            classified["last_seen_at"] = classified["occurred_at"]
            collapsed[key] = classified
            order.append(key)
            continue
        existing["occurrences"] += 1
        if classified["event_id"] not in existing["event_ids"]:
            existing["event_ids"].append(classified["event_id"])
        for field, pick in (("first_seen_at", min), ("last_seen_at", max)):
            values = [value for value in (existing[field], classified["occurred_at"]) if value is not None]
            existing[field] = pick(values) if values else None
    return [collapsed[key] for key in order]


def partition_audit_events(events: Any) -> dict[str, list[dict]]:
    """Split audit rows into actionable gate lanes; telemetry mirrors are excluded."""
    feeds: dict[str, list[dict]] = {lane: [] for lane in ("decisions", "denials", "gate_errors", "withdrawn", "service")}
    for event in events or ():
        if not isinstance(event, Mapping):
            continue
        lane_label = _AUDIT_LANES.get(str(event.get("event")))
        if lane_label is None:
            continue
        lane, label = lane_label
        metadata = event.get("metadata") if isinstance(event.get("metadata"), Mapping) else {}
        rule_id = _slug(metadata.get("rule_id"))
        control_key = _slug(metadata.get("key"))
        detail = rule_id or control_key
        feeds[lane].append({
            "seq": event.get("seq"),
            "event": _slug(event.get("event")) or UNDECLARED,
            "actor": _slug(event.get("actor")) or UNDECLARED,
            "request_id": _slug(event.get("request_id")),
            "at": event.get("at") if type(event.get("at")) is int else None,
            "lane": lane,
            "source": _LANE_SOURCES[lane],
            "is_policy_denial": lane == "denials",
            "is_gate_failure": lane == "gate_errors",
            "label": _bounded(f"{label} ({detail})" if detail else label) or label,
        })
    return feeds
