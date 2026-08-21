#!/usr/bin/env python3
"""Complete sanitized semantic record for the authenticated panel.

A semantic record projects everything Semantic Gate knows about one request -
catalogue metadata, bounded request content, identity binding, controls,
auto-approval evaluation, gate evidence, notification delivery, timestamps,
decision, outcome and audit correlation - into one canonical JSON document that
is safe to render in the authenticated panel without JavaScript.

Sanitization is fail-closed by construction: every projected value must pass a
closed, section-specific allowlist (slugs, hashes, enums, epochs, booleans) or
be schema-marked presentation-safe by the checked-in catalogue. Any other
request, gate, result, postcondition, error or audit content - including
CamelCase spellings, synonyms and arbitrary field names never seen before - is
replaced with explicit redaction metadata (``[redacted: reason; sha256=...;
chars=N]``) so a human can correlate content without reading it. Values that
look like credential material are redacted without a hash. Closed slug fields
also screen for credential patterns and high entropy; only explicit host
digest shapes (``req_<hex>``, ``notice_<hex>``, commit hashes) and known enum
values are exempt. Mapping keys are sanitized with the same policy. Depth, collection-size, per-section and
total serialized byte limits also fail closed with explicit markers. Internal
trusted context is never projected - only its hash appears.
"""
from __future__ import annotations

import hashlib
import html
import json
import math
import re
from datetime import datetime, timezone
from itertools import islice
from typing import Any, Mapping

from .autoapproval import COMMAND_FIELDS, SECRET_FIELDS
from .catalog import action_gate_class
from .projection import classify_observation, summarize_delivery

MAX_DEPTH = 6
MAX_ITEMS = 32
MAX_STRING = 300
MAX_KEY = 64
MAX_GATES = 16
MAX_AUDIT = 100
MAX_TELEMETRY = 32
MAX_NOTICES = 16
SECTION_MAX_BYTES = 49_152
RECORD_MAX_BYTES = 131_072
NOT_RECORDED = "not recorded"

TERMINAL_STATES = frozenset({"blocked", "cancelled", "simulated", "executed", "failed", "expired", "denied"})

_CONTROLS = frozenset({"policy", "ask", "step_up"})
_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_RISK = re.compile(r"R[0-9]\Z")
_NOTICE_STATES = frozenset({"pending", "delivered", "unknown"})
_DECISION_EVENTS = frozenset({"approved", "denied", "auto_approved"})

# Key-name tokens that are never rendered raw: credentials, secrets, commands,
# prompts, message bodies and content payloads. Keys are split on separators
# AND CamelCase boundaries, so ``accessToken``, ``cookieJar``, ``systemPrompt``,
# ``commandLine``, ``bodyText`` and ``file_text`` all fail closed.
_REDACTED_KEY_TOKENS = frozenset(SECRET_FIELDS) | frozenset(COMMAND_FIELDS) | frozenset({
    "password", "passwords", "passwd", "pwd", "passphrase", "key", "keys", "bearer",
    "basic", "signature", "jwt", "oauth", "otp", "totp", "mfa", "pin", "seed", "csrf",
    "cert", "certificate", "pem", "cookies", "sessions", "tokens",
    "prompt", "prompts", "body", "bodies", "message", "messages",
    "content", "contents", "text", "stdin", "stdout", "stderr", "env", "environ",
    "payload", "blob", "binary",
})
# Values that look like credential material are redacted regardless of key
# name, and never hashed (a hash of a guessable secret invites offline search).
_SECRET_VALUE = re.compile(
    r"(?i)(\bbearer\s|\bbasic\s+[a-z0-9+/=_-]{6,}|sk-|ghp_|gho_|github_pat_|xox[baprs]-|"
    r"AKIA[0-9A-Z]{12,}|-----begin |eyJ[A-Za-z0-9_-]{16,}|\bpassword\s*[=:])")
_KEY_SPLIT = re.compile(r"[^a-z0-9]+")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SAFE_KEY = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:@/-]{0,63}\Z")
_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
# Conservative printable charset for schema-marked presentation-safe text.
_PRESENTATION_ALLOWED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,:;!?()[]/@#+_'\"%$*=-"
)


def _marker(reason: str) -> str:
    return f"[redacted: {reason}]"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _looks_high_entropy(value: str) -> bool:
    """Treat long mixed-alphabet substrings as credential material.

    Inspect substrings rather than the whole label so punctuation cannot hide a
    token inside an otherwise slug-shaped value (for example ``tag:<token>``).
    """
    for match in _ENTROPY_TOKEN.finditer(value.strip()):
        candidate = match.group(0)
        classes = sum((any(c.islower() for c in candidate), any(c.isupper() for c in candidate),
                       any(c.isdigit() for c in candidate)))
        if classes >= 3 or (classes >= 2 and len(candidate) >= 32):
            return True
    return False


def _is_secretlike(value: str) -> bool:
    return bool(_SECRET_VALUE.search(value)) or _looks_high_entropy(value)


def redaction_fingerprint(value: str, reason: str) -> str:
    """Explicit redaction metadata for arbitrary content: reason, hash, length."""
    if _is_secretlike(value):
        return _marker("value matches secret material patterns")
    return f"[redacted: {reason}; sha256={_digest(value)}; chars={len(value)}]"


def presentation_safe_text(value: Any, limit: int = 160) -> str | None:
    """Bounded, screened text for schema-marked presentation-safe metadata.

    Returns None unless the value is a non-secret-looking string; disallowed
    characters are dropped, whitespace collapses and the length is bounded.
    """
    if not isinstance(value, str) or not value or _is_secretlike(value):
        return None
    kept = "".join(ch if ch in _PRESENTATION_ALLOWED else " " if ch.isspace() else "" for ch in value)
    collapsed = " ".join(kept.split())
    if not collapsed or _is_secretlike(collapsed):
        return None
    return collapsed if len(collapsed) <= limit else collapsed[:limit - 3].rstrip() + "..."


def _key_tokens(key: str) -> list[str]:
    normalized = _CAMEL_BOUNDARY.sub("_", key).casefold()
    return [token for token in _KEY_SPLIT.split(normalized) if token]


def _key_redaction(key: str, sensitive_fields: frozenset[str]) -> str | None:
    lowered = key.casefold()
    if lowered == "trusted_context":
        return "internal trusted context; only its hash is shown"
    if key in sensitive_fields or lowered in sensitive_fields:
        return "schema-marked sensitive parameter"
    if lowered in _REDACTED_KEY_TOKENS:
        return "sensitive field name"
    if any(token in _REDACTED_KEY_TOKENS for token in _key_tokens(key)):
        return "sensitive field name"
    return None


def _safe_key(key: str) -> str:
    """Mapping keys themselves may carry content; non-label keys become metadata."""
    if _SAFE_KEY.fullmatch(key) and not _is_secretlike(key):
        return key
    return f"[redacted key: sha256={_digest(key)}]"


def sanitize_semantic_value(value: Any, *, sensitive_fields: frozenset[str] = frozenset(),
                            safe_fields: frozenset[str] = frozenset(), _depth: int = 0,
                            _key: str | None = None) -> Any:
    """Fail-closed projection of one JSON-ish value.

    Structure, booleans and bounded numbers are kept. Every string becomes
    explicit redaction metadata unless its field name is schema-marked
    presentation-safe (``safe_fields``), in which case it is screened, bounded
    and rendered. Mapping keys are sanitized with the same policy.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if -(2 ** 63) <= value <= 2 ** 63 - 1 else _marker("integer out of bounds")
    if isinstance(value, float):
        return value if math.isfinite(value) else _marker("non-finite number")
    if isinstance(value, (bytes, bytearray)):
        return _marker("binary content")
    if isinstance(value, str):
        if not value:
            return value
        if _key is not None and _key in safe_fields:
            screened = presentation_safe_text(value, limit=MAX_STRING)
            if screened is not None:
                return screened
        return redaction_fingerprint(value, "unlisted content")
    if isinstance(value, Mapping):
        if _depth >= MAX_DEPTH:
            return _marker(f"depth limit {MAX_DEPTH} exceeded")
        items = sorted(value.items(), key=lambda pair: str(pair[0]))
        projected: dict[str, Any] = {}
        for key, item in items[:MAX_ITEMS]:
            key_text = str(key)
            reason = _key_redaction(key_text, sensitive_fields)
            rendered_key = _safe_key(key_text)
            while rendered_key in projected:
                rendered_key += "+"
            projected[rendered_key] = _marker(reason) if reason else sanitize_semantic_value(
                item, sensitive_fields=sensitive_fields, safe_fields=safe_fields,
                _depth=_depth + 1, _key=key_text)
        if len(items) > MAX_ITEMS:
            projected["[redacted: size limit]"] = f"{len(items) - MAX_ITEMS} additional entries omitted"
        return projected
    if isinstance(value, (list, tuple)):
        if _depth >= MAX_DEPTH:
            return _marker(f"depth limit {MAX_DEPTH} exceeded")
        projected_list = [sanitize_semantic_value(item, sensitive_fields=sensitive_fields,
                                                  safe_fields=safe_fields, _depth=_depth + 1, _key=_key)
                          for item in value[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            projected_list.append(_marker(f"{len(value) - MAX_ITEMS} additional items omitted"))
        return projected_list
    return _marker(f"unsupported type {type(value).__name__}")


def _slug(value: Any) -> str | None:
    """Closed label positions: low-entropy host vocabulary only.

    Fails closed on both the known secret-material patterns and the entropy
    heuristic, so a credential pasted into a label-shaped field (error_type,
    reason, actor, ...) never renders. Hash-derived host identifiers must go
    through :func:`_identifier`, which exempts only its explicit digest shapes.
    """
    if isinstance(value, str) and _SLUG.fullmatch(value) and not _is_secretlike(value):
        return value
    return None


# Host-generated identifiers are prefixed hex digests (req_<hex>, notice_<hex>,
# approval_<hex>) or bare hex digests (commit). Only these exact shapes are
# exempt from the entropy heuristic; every other high-entropy string fails closed.
_ID_DIGEST = re.compile(r"(?:[a-z][a-z0-9]{0,31}_)?[0-9a-f]{6,64}\Z")


def _identifier(value: Any) -> str | None:
    """Closed identifier positions: explicit digest shapes or screened slugs."""
    if not isinstance(value, str) or _SECRET_VALUE.search(value):
        return None
    if _ID_DIGEST.fullmatch(value):
        return value
    return _slug(value)


def _hash(value: Any) -> str | None:
    return value if isinstance(value, str) and _HASH.fullmatch(value) else None


def _policy_text(value: Any, limit: int = MAX_STRING) -> Any:
    """Bounded rendering for host-owned catalogue/policy text; never raw passthrough."""
    if not isinstance(value, str) or not value:
        return NOT_RECORDED
    return presentation_safe_text(value, limit=limit) or _marker("policy text failed screening")


def _epoch(value: Any) -> int | None:
    return value if type(value) is int else None


def _utc(value: Any) -> str:
    if type(value) is not int:
        return NOT_RECORDED
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Closed vocabulary for gate evidence and decision audit metadata. A field
# outside these sets - or one whose value fails its validator - fails closed.
_CLOSED_BOOL = frozenset({"normalized", "delivered", "retry_allowed", "authorizes_execution",
                          "matched", "bound", "simulated", "auto_approved"})
# Enum fields render only their exact known values; anything else fails closed.
_CLOSED_ENUM = {"decision": frozenset({"approve", "deny"}), "assurance": frozenset({"ask", "step_up"})}
# Identifier fields legitimately carry hash-derived tokens; they pass only the
# explicit digest shapes in _ID_DIGEST or the fully screened slug vocabulary.
_CLOSED_ID = frozenset({"notification_id", "evidence_id", "approval_gate_id", "request_id",
                        "notification_gate_id", "rule_id", "commit", "blocked_by"})
# Label fields are screened slugs: secret-material patterns AND entropy fail closed.
_CLOSED_SLUG = frozenset({"tool", "level", "reason", "error_type", "actor",
                          "reason_code", "authority", "action_class", "key"})
_CLOSED_HASH = frozenset({"request_hash", "template_hash", "arguments_hash"})
_CLOSED_EPOCH = frozenset({"ttl_seconds", "expires_at", "consumed_at", "decided_at", "checked_at",
                           "delivered_at", "rule_version", "policy_version", "occurred_at",
                           "attempts", "seq", "version"})
_CLOSED_NESTED = frozenset({"result", "actual", "value", "metadata"})


def _closed_section(value: Any, *, sensitive_fields: frozenset[str],
                    safe_recipients: frozenset[str] = frozenset()) -> Any:
    """Project a mapping through the closed evidence/audit vocabulary."""
    if value is None:
        return None
    if not isinstance(value, Mapping):
        return sanitize_semantic_value(value, sensitive_fields=sensitive_fields)
    projected: dict[str, Any] = {}
    items = sorted(value.items(), key=lambda pair: str(pair[0]))
    for key, item in items[:MAX_ITEMS]:
        key_text = str(key)
        rendered_key = _safe_key(key_text)
        while rendered_key in projected:
            rendered_key += "+"
        reason = _key_redaction(key_text, sensitive_fields)
        if reason:
            projected[rendered_key] = _marker(reason)
        elif key_text in _CLOSED_BOOL:
            projected[rendered_key] = item if isinstance(item, bool) else _marker("invalid boolean field")
        elif key_text in _CLOSED_ENUM:
            if item is None or (isinstance(item, str) and item in _CLOSED_ENUM[key_text]):
                projected[rendered_key] = item
            else:
                projected[rendered_key] = (redaction_fingerprint(item, "value outside the closed enum")
                                           if isinstance(item, str) else _marker("invalid enum field"))
        elif key_text == "recipient":
            if isinstance(item, str) and item in safe_recipients:
                projected[rendered_key] = presentation_safe_text(item) or NOT_RECORDED
            elif isinstance(item, str) and item:
                projected[rendered_key] = redaction_fingerprint(
                    item, "notification recipient not presentation-authorized")
            else:
                projected[rendered_key] = NOT_RECORDED
        elif key_text in _CLOSED_ID or key_text in _CLOSED_SLUG:
            validator = _identifier if key_text in _CLOSED_ID else _slug
            projected[rendered_key] = validator(item) if item is not None else None
            if item is not None and projected[rendered_key] is None:
                projected[rendered_key] = (redaction_fingerprint(item, "unlisted content")
                                           if isinstance(item, str) else _marker("invalid identifier field"))
        elif key_text in _CLOSED_HASH:
            projected[rendered_key] = _hash(item) or _marker("invalid hash field")
        elif key_text in _CLOSED_EPOCH:
            projected[rendered_key] = item if type(item) is int else _marker("invalid integer field")
        elif key_text in _CLOSED_NESTED:
            projected[rendered_key] = sanitize_semantic_value(item, sensitive_fields=sensitive_fields, _depth=1)
        else:
            projected[rendered_key] = sanitize_semantic_value(item, sensitive_fields=sensitive_fields, _depth=1)
    if len(items) > MAX_ITEMS:
        projected["[redacted: size limit]"] = f"{len(items) - MAX_ITEMS} additional entries omitted"
    return projected


def _catalogue_section(action: Any, entry: Mapping[str, Any]) -> dict:
    derived_domain = action.split(".", 1)[0] if isinstance(action, str) and "." in action else None
    privacy = entry.get("privacy_classes")
    privacy_classes = [item for item in (privacy if isinstance(privacy, (list, tuple)) else ())
                       if _slug(item)][:16]
    constraints = entry.get("constraints")
    constraints = [text for text in (_policy_text(item) for item in
                                     (constraints if isinstance(constraints, (list, tuple)) else ())[:16])
                   if text != NOT_RECORDED]
    return {
        "action": _slug(action) or NOT_RECORDED,
        "catalogued": bool(entry),
        "domain": _slug(entry.get("domain")) or _slug(derived_domain) or NOT_RECORDED,
        "summary": _policy_text(entry.get("summary")),
        "effect": _slug(entry.get("effect")) or NOT_RECORDED,
        "risk": entry["risk"] if isinstance(entry.get("risk"), str) and _RISK.fullmatch(entry["risk"]) else NOT_RECORDED,
        "gate_class": action_gate_class(entry) or NOT_RECORDED,
        "privacy_classes": privacy_classes,
        "constraints": constraints,
    }


def _bounded_rows(source: Any, cap: int) -> tuple[list[Any], bool]:
    """Consume at most ``cap + 1`` items from an untrusted iterable.

    Never materializes the full input; the single extra item only proves
    truncation, so unbounded or adversarial iterables cannot exhaust memory.
    """
    rows = list(islice(iter(source or ()), cap + 1))
    return rows[:cap], len(rows) > cap


def _telemetry_record(row: Any) -> dict:
    """Re-project content-free telemetry through this record's stricter validators."""
    classified = classify_observation(row)
    return {
        "category": "execution_telemetry",
        "source": "tool telemetry",
        "is_gate_failure": False,
        "is_policy_denial": False,
        "label": _policy_text(classified.get("label")),
        "operation": _slug(classified.get("operation")) or NOT_RECORDED,
        "semantic_class": _slug(classified.get("semantic_class")) or NOT_RECORDED,
        "outcome": _slug(classified.get("outcome")) or NOT_RECORDED,
        "principal": _slug(classified.get("principal")) or NOT_RECORDED,
        "correlation_id": _identifier(classified.get("correlation_id")) or NOT_RECORDED,
        "event_id": _identifier(classified.get("event_id")) or NOT_RECORDED,
        "occurred_at": (classified.get("occurred_at")
                        if type(classified.get("occurred_at")) is int else None),
    }


def _notices_section(rows: list[Any], *, safe_recipients: frozenset[str]) -> list[dict]:
    """Allowlisted projection of pre-bounded outbox rows; claim tokens never appear."""
    notices = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        last_error = row.get("last_error")
        recipient = row.get("recipient")
        if isinstance(recipient, str) and recipient in safe_recipients:
            rendered_recipient = presentation_safe_text(recipient) or NOT_RECORDED
        elif isinstance(recipient, str) and recipient:
            rendered_recipient = redaction_fingerprint(
                recipient, "notification recipient not presentation-authorized")
        else:
            rendered_recipient = NOT_RECORDED
        notices.append({
            "notification_id": _identifier(row.get("notification_id")) or NOT_RECORDED,
            "recipient": rendered_recipient,
            "state": row.get("state") if row.get("state") in _NOTICE_STATES else "unknown",
            "attempts": row.get("attempts") if type(row.get("attempts")) is int else 0,
            "created_at_utc": _utc(row.get("created_at")),
            "delivered_at_utc": _utc(row.get("delivered_at")),
            "next_attempt_at_utc": _utc(row.get("next_attempt_at")),
            "last_error": redaction_fingerprint(last_error, "provider error content")
            if isinstance(last_error, str) and last_error else None,
        })
    return notices


def _idempotency(value: Any) -> str:
    """Caller-chosen idempotency keys: slug-shaped low-entropy keys render, others fingerprint."""
    if not isinstance(value, str) or not value:
        return NOT_RECORDED
    if _is_secretlike(value):
        return _marker("value matches secret material patterns")
    return _slug(value) or redaction_fingerprint(value, "unlisted idempotency key")


def schema_safe_fields(entry: Mapping[str, Any]) -> frozenset[str]:
    """Field names the checked-in catalogue explicitly marks presentation-safe."""
    declared = entry.get("presentation_safe_parameters")
    return frozenset(field for field in (declared if isinstance(declared, (list, tuple)) else ())
                     if isinstance(field, str))


def schema_safe_notification_recipients(entry: Mapping[str, Any]) -> frozenset[str]:
    """Notification recipients explicitly approved for authenticated display."""
    declared = entry.get("presentation_safe_notification_recipients")
    return frozenset(value for value in (declared if isinstance(declared, (list, tuple)) else ())
                     if isinstance(value, str) and presentation_safe_text(value) == value)


def _safe_target(parameters: Mapping[str, Any], entry: Mapping[str, Any]) -> Any:
    """Render the target only when it exactly matches the catalogue's closed value list."""
    presentation = entry.get("presentation")
    presentation = presentation if isinstance(presentation, Mapping) else {}
    field = presentation.get("safe_target_field")
    allowed = presentation.get("safe_target_values")
    target = parameters.get("target")
    if (field == "target" and isinstance(allowed, (list, tuple)) and isinstance(target, str)
            and target in [item for item in allowed if isinstance(item, str)]):
        return presentation_safe_text(target) or NOT_RECORDED
    if not isinstance(target, str) or not target:
        return NOT_RECORDED
    return redaction_fingerprint(target, "target not in the catalogue safe-value list")


def enforce_record_bounds(record: Mapping[str, Any], *, section_max_bytes: int = SECTION_MAX_BYTES,
                          record_max_bytes: int = RECORD_MAX_BYTES) -> dict:
    """Fail closed on serialized size: oversized sections and records become markers."""
    bounded: dict[str, Any] = {}
    for section, value in record.items():
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        if len(encoded) > section_max_bytes:
            bounded[section] = {"redacted": _marker(f"section exceeds {section_max_bytes} serialized bytes"),
                                "sha256": _digest(encoded), "bytes": len(encoded)}
        else:
            bounded[section] = value
    total = json.dumps(bounded, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if len(total) > record_max_bytes:
        return {"record_version": record.get("record_version", 1),
                "identity": bounded.get("identity", {}),
                "redacted": _marker(f"record exceeds {record_max_bytes} serialized bytes"),
                "bytes": len(total)}
    return bounded


def build_semantic_record(request: Mapping[str, Any], *, catalog: Any, node: Any = None,
                          audit_events: Any = (), notifications: Any = (), telemetry: Any = ()) -> dict:
    """Project one request snapshot into the complete sanitized semantic record.

    Every value in the returned document either passes a closed section-specific
    allowlist or becomes explicit redaction metadata; the raw snapshot is never
    embedded. Gate, audit, telemetry and notification inputs are capped before
    any traversal (at most cap + 1 items are consumed from each iterable, the
    extra item marking truncation) and the finished record is byte-bounded per
    section and in total.
    """
    if not isinstance(request, Mapping):
        raise ValueError("request snapshot must be a mapping")
    action = request.get("action")
    actions = catalog.get("actions") if isinstance(catalog, Mapping) else None
    entry = actions.get(action) if isinstance(actions, Mapping) and isinstance(action, str) else None
    entry = entry if isinstance(entry, Mapping) else {}
    sensitive = frozenset(str(field) for field in (entry.get("sensitive_parameters") or ())
                          if isinstance(field, str))
    safe_fields = schema_safe_fields(entry)
    safe_notification_recipients = schema_safe_notification_recipients(entry)
    parameters = request.get("parameters") if isinstance(request.get("parameters"), Mapping) else {}
    extra = {key: value for key, value in parameters.items() if key not in {"summary", "target", "details"}}

    # Cap unbounded inputs BEFORE any traversal or materialization: at most
    # cap + 1 items are ever consumed from each iterable; the extra item only
    # marks truncation in the omissions section.
    gate_rows, gates_truncated = _bounded_rows(request.get("gates"), MAX_GATES)
    audit_rows, audit_truncated = _bounded_rows(audit_events, MAX_AUDIT)
    telemetry_rows, telemetry_truncated = _bounded_rows(telemetry, MAX_TELEMETRY)
    notice_rows, notices_truncated = _bounded_rows(notifications, MAX_NOTICES)
    omissions = {"gates": gates_truncated, "audit_events": audit_truncated,
                 "linked_telemetry": telemetry_truncated, "notices": notices_truncated}

    gates = []
    approval_evidence: Mapping[str, Any] = {}
    execute_evidence: Mapping[str, Any] = {}
    for gate in gate_rows:
        if not isinstance(gate, Mapping):
            continue
        evidence = gate.get("evidence")
        gates.append({
            "id": _identifier(gate.get("id")) or NOT_RECORDED,
            "kind": _slug(gate.get("kind")) or NOT_RECORDED,
            "status": _slug(gate.get("status")) or NOT_RECORDED,
            "evidence": _closed_section(evidence, sensitive_fields=sensitive,
                                        safe_recipients=safe_notification_recipients),
        })
        if isinstance(evidence, Mapping):
            if gate.get("kind") == "approval":
                approval_evidence = evidence
            elif gate.get("kind") == "execute":
                execute_evidence = evidence

    audit = []
    decision_event = None
    for event in audit_rows:
        if not isinstance(event, Mapping):
            continue
        row = {
            "seq": event.get("seq") if type(event.get("seq")) is int else None,
            "event": _slug(event.get("event")) or NOT_RECORDED,
            "actor": _slug(event.get("actor")) or NOT_RECORDED,
            "at": _epoch(event.get("at")),
            "at_utc": _utc(event.get("at")),
            "metadata": _closed_section(event.get("metadata"), sensitive_fields=sensitive,
                                        safe_recipients=safe_notification_recipients),
        }
        audit.append(row)
        if event.get("event") in _DECISION_EVENTS:
            decision_event = row

    linked_telemetry = []
    for row in telemetry_rows:
        try:
            linked_telemetry.append(_telemetry_record(row))
        except ValueError:
            continue

    challenge = request.get("approval_challenge")
    challenge = challenge if isinstance(challenge, Mapping) else {}
    expires_at = _epoch(challenge.get("expires_at"))
    if expires_at is None:
        expires_at = _epoch(approval_evidence.get("expires_at"))
    decided_at = _epoch(approval_evidence.get("consumed_at")) or _epoch(approval_evidence.get("decided_at"))
    if decided_at is None and decision_event is not None:
        decided_at = decision_event["at"]

    auto = request.get("auto_approval") if isinstance(request.get("auto_approval"), Mapping) else None
    gate_class = entry.get("gate_class")
    if gate_class == "human_communication":
        gate_class_reason = "communication_requires_human"
    elif gate_class == "human_spending":
        gate_class_reason = "spending_requires_human"
    elif gate_class == "prohibited":
        gate_class_reason = "action_prohibited"
    else:
        gate_class_reason = None
    auto_section = {
        "evaluated": auto is not None,
        "matched": (auto.get("matched") is True) if auto is not None else None,
        "reason_code": _slug(auto.get("reason_code")) if auto is not None else None,
        "reason": (_policy_text(auto.get("reason")) if isinstance(auto.get("reason"), str) else None)
        if auto is not None else None,
        "classification_reason_code": gate_class_reason,
        "rule_id": _slug(auto.get("rule_id")) if auto is not None else None,
        "rule_version": (auto.get("rule_version") if type(auto.get("rule_version")) is int else None) if auto is not None else None,
        "authorizes_execution": (auto or {}).get("authorizes_execution") is True,
    }

    assurance = approval_evidence.get("assurance")
    decision_value = approval_evidence.get("decision")
    decision_section = {
        "decided": decision_event is not None or (
            isinstance(decision_value, str) and decision_value in {"approve", "deny"}
        ),
        "event": decision_event["event"] if decision_event is not None else None,
        "actor": _slug(approval_evidence.get("actor")) or (decision_event["actor"] if decision_event is not None else None),
        "assurance": assurance if assurance in {"ask", "step_up"} else None,
        "decided_at_utc": _utc(decided_at),
    }

    would_call = request.get("would_call") if isinstance(request.get("would_call"), Mapping) else {}
    state = _slug(request.get("state")) or NOT_RECORDED
    # One bounded materialization feeds both projections: a one-shot iterator
    # must not be consumed twice (notices would drain it before the summary).
    notices = _notices_section(notice_rows, safe_recipients=safe_notification_recipients)
    delivery = summarize_delivery(notice_rows)

    record = {
        "record_version": 1,
        "identity": {
            "request_id": _identifier(request.get("request_id")) or NOT_RECORDED,
            "request_hash": _hash(request.get("request_hash")) or NOT_RECORDED,
            "idempotency_key": _idempotency(request.get("idempotency_key")),
            "trusted_context_hash": _hash(request.get("trusted_context_hash")) or NOT_RECORDED,
        },
        "catalogue": _catalogue_section(action, entry),
        "request": {
            "summary": sanitize_semantic_value(parameters.get("summary"), sensitive_fields=sensitive,
                                               safe_fields=safe_fields, _key="summary")
            if parameters.get("summary") is not None else NOT_RECORDED,
            "target": _safe_target(parameters, entry),
            "details": sanitize_semantic_value(parameters.get("details"), sensitive_fields=sensitive,
                                               safe_fields=safe_fields),
            "additional_parameters": sanitize_semantic_value(extra, sensitive_fields=sensitive,
                                                             safe_fields=safe_fields),
            "context": sanitize_semantic_value(request.get("context"), sensitive_fields=sensitive),
        },
        "principal": {
            "requester": _slug(request.get("requester")) or NOT_RECORDED,
            "node": _slug(node) or NOT_RECORDED,
        },
        "control": {
            "minimum_control": request.get("minimum_control") if request.get("minimum_control") in _CONTROLS else NOT_RECORDED,
            "policy_control": request.get("policy_control") if request.get("policy_control") in _CONTROLS else NOT_RECORDED,
            "effective_control": request.get("effective_control") if request.get("effective_control") in _CONTROLS else NOT_RECORDED,
        },
        "auto_approval": auto_section,
        "gates": gates,
        "notification_delivery": {
            "state": delivery["state"],
            "message": delivery["message"],
            "attempts": delivery["attempts"],
            "notices": notices,
        },
        "timestamps": {
            "created_at": _epoch(request.get("created_at")),
            "created_at_utc": _utc(request.get("created_at")),
            "updated_at": _epoch(request.get("updated_at")),
            "updated_at_utc": _utc(request.get("updated_at")),
            "approval_expires_at": expires_at,
            "approval_expires_at_utc": _utc(expires_at),
            "decided_at": decided_at,
            "decided_at_utc": _utc(decided_at),
        },
        "decision": decision_section,
        "outcome": {
            "state": state,
            "terminal": state in TERMINAL_STATES,
            "execution_possible": request.get("execution_possible") is True,
            "authorizes_execution": auto_section["authorizes_execution"] or approval_evidence.get("authorizes_execution") is True,
            "blocked_by": _identifier(request.get("blocked_by")),
            "would_call_tool": _slug(would_call.get("tool")),
            "arguments_hash": _hash(execute_evidence.get("arguments_hash")),
            "execution_result": sanitize_semantic_value(request.get("execution_result"), sensitive_fields=sensitive)
            if request.get("execution_result") is not None else None,
            "postconditions": sanitize_semantic_value(request.get("postconditions"), sensitive_fields=sensitive)
            if request.get("postconditions") is not None else None,
        },
        "audit": audit,
        "linked_telemetry": linked_telemetry,
        "omissions": omissions,
    }
    return enforce_record_bounds(record)


def canonical_record_json(record: Mapping[str, Any]) -> str:
    """Deterministic, human-readable canonical JSON for the no-JavaScript fallback."""
    return json.dumps(record, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)


def render_semantic_record_html(record: Mapping[str, Any], *, detail_href: str | None = None,
                                open_by_default: bool = False) -> str:
    """Render the record as an escaped, expandable no-JavaScript HTML fragment."""
    note = ("<p class=muted>Sanitized record: request, gate, result, error and audit content outside the "
            "closed allowlists is replaced with explicit [redacted] fingerprint markers; internal trusted "
            "context appears only as its hash.</p>")
    link = (f"<p><a href='{html.escape(detail_href, quote=True)}'>Open the stable record page</a></p>"
            if detail_href else "")
    # Element content inside <pre>: & < > must be escaped; quotes stay readable.
    encoded = html.escape(canonical_record_json(record), quote=False)
    return (f"<details class=semantic-record{' open' if open_by_default else ''}>"
            f"<summary>Full semantic record</summary>{note}{link}"
            f"<pre class=record>{encoded}</pre></details>")
