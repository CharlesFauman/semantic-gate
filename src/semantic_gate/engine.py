"""Generic deterministic gate engine.

The engine is framework-agnostic. Agents may propose and inspect requests, but
human approval enters through a host-only method and execution additionally
requires an in-process authority object that is never serializable through MCP.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Mapping


class GatePolicyError(ValueError):
    """Policy, request, or deterministic gate validation failed."""


class ApprovalRejected(GatePolicyError):
    """Approval evidence was invalid, expired, replayed, or misbound."""


@dataclass(frozen=True)
class ExecutionAuthority:
    """Host-owned authority required in addition to an execution-enabled policy."""

    issuer: str

    def __post_init__(self) -> None:
        if not isinstance(self.issuer, str) or not self.issuer.strip():
            raise GatePolicyError("execution authority issuer must be non-empty")


class DenyAllApprovalVerifier:
    """Safe default: no evidence is trusted until a host installs a verifier."""

    def verify(self, evidence: dict, request: dict) -> bool:
        return False


class RecordingNotifier:
    """In-memory notifier used by dry-run hosts and examples."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def notify(self, request: dict, gate: dict) -> dict:
        event = {
            "notification_id": "notice_" + hashlib.sha256(
                f"{request['request_hash']}:{gate['id']}".encode("utf-8")
            ).hexdigest()[:20],
            "request_id": request["request_id"],
            "request_hash": request["request_hash"],
            "notification_gate_id": gate["id"],
            "recipient": gate["recipient"],
            "template": gate["template"],
            "template_hash": hashlib.sha256(gate["template"].encode("utf-8")).hexdigest(),
            "delivered_at": None,
            "delivered": False,
            "simulation_only": True,
        }
        self.events.append(event)
        return dict(event)


class ToolRegistry:
    """Host-owned registry separating read preconditions from effectful targets."""

    def __init__(self) -> None:
        self._read: dict[str, Callable[[dict], dict]] = {}
        self._targets: dict[str, Callable[[dict], dict]] = {}

    def register_read(self, name: str, function: Callable[[dict], dict]) -> None:
        self._register(self._read, name, function)

    def register_target(self, name: str, function: Callable[[dict], dict]) -> None:
        self._register(self._targets, name, function)

    @staticmethod
    def _register(destination: dict, name: str, function: Callable[[dict], dict]) -> None:
        if not isinstance(name, str) or not name or not callable(function):
            raise GatePolicyError("registered tool requires a non-empty name and callable")
        if name in destination:
            raise GatePolicyError(f"tool already registered: {name}")
        destination[name] = function

    def call_read(self, name: str, arguments: dict) -> dict:
        if not isinstance(name, str) or not name:
            raise GatePolicyError("read gate tool name must be a non-empty string")
        if name not in self._read:
            raise GatePolicyError(f"read gate tool is not registered: {name}")
        result = self._read[name](_copy(arguments))
        if not isinstance(result, dict):
            raise GatePolicyError(f"read gate tool must return an object: {name}")
        return _copy(result)

    def call_target(self, name: str, arguments: dict) -> dict:
        if not isinstance(name, str) or not name:
            raise GatePolicyError("target tool name must be a non-empty string")
        if name not in self._targets:
            raise GatePolicyError(f"target tool is not registered: {name}")
        result = self._targets[name](_copy(arguments))
        if not isinstance(result, dict):
            raise GatePolicyError(f"target tool must return an object: {name}")
        return _copy(result)


_ACTION = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")
_TOP_FIELDS = {"version", "mode", "execution_enabled", "workflows"}
_WORKFLOW_FIELDS = {"description", "principals", "target_tool", "parameter_schema", "gates"}
_GATE_FIELDS = {
    "schema": {"id", "kind", "requires"},
    "condition": {"id", "kind", "requires", "path", "op", "value"},
    "tool": {"id", "kind", "requires", "tool", "input", "expect", "recheck"},
    "notify": {"id", "kind", "requires", "recipient", "template"},
    "approval": {"id", "kind", "requires", "level", "ttl_seconds"},
    "execute": {"id", "kind", "requires", "tool", "simulation_only"},
}


MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000
MAX_JSON_COLLECTION_ITEMS = 10_000
MAX_JSON_STRING_CHARS = 65_536
MAX_JSON_INTEGER = 2**63 - 1


def _is_finite_number(value: Any) -> bool:
    return type(value) is int or (type(value) is float and math.isfinite(value))


def _validate_json_value(value: Any) -> None:
    nodes = 0

    def validate(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise GatePolicyError("JSON value has too many nodes")
        if depth > MAX_JSON_DEPTH:
            raise GatePolicyError("JSON value is nested too deeply")
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, str):
            if len(item) > MAX_JSON_STRING_CHARS:
                raise GatePolicyError("JSON string is too long")
            return
        if type(item) is int:
            if item < -MAX_JSON_INTEGER - 1 or item > MAX_JSON_INTEGER:
                raise GatePolicyError("JSON integer is outside the signed 64-bit range")
            return
        if type(item) is float:
            if not math.isfinite(item):
                raise GatePolicyError("non-finite JSON numbers are forbidden")
            return
        if isinstance(item, Mapping):
            if len(item) > MAX_JSON_COLLECTION_ITEMS:
                raise GatePolicyError("JSON object has too many members")
            if any(not isinstance(key, str) for key in item):
                raise GatePolicyError("JSON object keys must be strings")
            for key, nested in item.items():
                validate(key, depth + 1)
                validate(nested, depth + 1)
            return
        if isinstance(item, list):
            if len(item) > MAX_JSON_COLLECTION_ITEMS:
                raise GatePolicyError("JSON array has too many items")
            for nested in item:
                validate(nested, depth + 1)
            return
        raise GatePolicyError(f"value is not a JSON type: {type(item).__name__}")

    validate(value, 0)


def _copy(value: Any) -> Any:
    _validate_json_value(value)
    try:
        return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))
    except (TypeError, ValueError) as error:
        raise GatePolicyError(f"value must be JSON-serializable: {error}") from error


CONTROL_RANK = {"ask": 1, "step_up": 2}


def _effective_workflow(workflow: Mapping[str, Any], minimum_control: str) -> tuple[dict, str, str]:
    if not isinstance(minimum_control,str) or minimum_control not in {"policy", "ask", "step_up"}:
        raise GatePolicyError("minimum_control must be policy, ask, or step_up")
    effective = _copy(workflow)
    approvals = [gate for gate in effective["gates"] if gate["kind"] == "approval"]
    if not approvals:
        raise GatePolicyError("workflow has no approval gate to satisfy minimum_control")
    policy_rank = max(2 if gate["level"] == "human_step_up" else 1 for gate in approvals)
    requested_rank = policy_rank if minimum_control == "policy" else CONTROL_RANK[minimum_control]
    effective_rank = max(policy_rank, requested_rank)
    if effective_rank == 2:
        for gate in approvals:
            gate["level"] = "human_step_up"
            gate["ttl_seconds"] = min(gate["ttl_seconds"], 300)
    policy_control = "step_up" if policy_rank == 2 else "ask"
    effective_control = "step_up" if effective_rank == 2 else "ask"
    return effective, policy_control, effective_control


def _canonical(value: Any) -> str:
    _validate_json_value(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise GatePolicyError(f"value must be JSON-serializable: {error}") from error


def _exact_fields(value: Mapping[str, Any], allowed: set[str], context: str) -> None:
    unknown = set(value) - allowed
    missing = allowed - set(value)
    if unknown:
        raise GatePolicyError(f"unknown {context} field(s): {', '.join(sorted(unknown))}")
    if missing:
        raise GatePolicyError(f"missing {context} field(s): {', '.join(sorted(missing))}")


def _reject_nonfinite_constant(value: str) -> None:
    raise GatePolicyError(f"non-finite JSON number is forbidden: {value}")


def _load_policy(source: str | Path | Mapping[str, Any]) -> dict:
    """Load and validate a closed workflow policy."""
    if isinstance(source, (str, Path)):
        with Path(source).open("r", encoding="utf-8") as handle:
            raw = json.load(handle, parse_constant=_reject_nonfinite_constant)
    else:
        raw = source
    if not isinstance(raw, Mapping):
        raise GatePolicyError("policy must be an object")
    _validate_json_value(raw)
    _exact_fields(raw, _TOP_FIELDS, "policy")
    if type(raw["version"]) is not int or raw["version"] != 1:
        raise GatePolicyError("version must be integer 1")
    if raw["mode"] not in {"simulation_only", "enforcing"}:
        raise GatePolicyError("mode must be simulation_only or enforcing")
    if not isinstance(raw["execution_enabled"], bool):
        raise GatePolicyError("execution_enabled must be boolean")
    if raw["mode"] == "simulation_only" and raw["execution_enabled"]:
        raise GatePolicyError("simulation_only policy cannot enable execution")
    if not isinstance(raw["workflows"], Mapping) or not raw["workflows"]:
        raise GatePolicyError("workflows must be a non-empty object")

    for action, workflow in raw["workflows"].items():
        if not isinstance(action, str) or not _ACTION.fullmatch(action):
            raise GatePolicyError(f"invalid semantic action: {action!r}")
        if not isinstance(workflow, Mapping):
            raise GatePolicyError(f"workflow {action} must be an object")
        _exact_fields(workflow, _WORKFLOW_FIELDS, f"workflow {action}")
        if not isinstance(workflow["description"], str) or not workflow["description"].strip():
            raise GatePolicyError(f"workflow {action} description must be non-empty")
        if (
            not isinstance(workflow["principals"], list)
            or not workflow["principals"]
            or any(not isinstance(item, str) or not item for item in workflow["principals"])
            or len(workflow["principals"]) != len(set(workflow["principals"]))
        ):
            raise GatePolicyError(f"workflow {action} principals must be a unique non-empty string list")
        if "*" in workflow["principals"] and len(workflow["principals"]) != 1:
            raise GatePolicyError(f"workflow {action} wildcard principal cannot be combined with named principals")
        if not isinstance(workflow["target_tool"], str) or not workflow["target_tool"]:
            raise GatePolicyError(f"workflow {action} target_tool must be non-empty")
        _validate_schema_shape(workflow["parameter_schema"], action)
        gates = workflow["gates"]
        if not isinstance(gates, list) or not gates:
            raise GatePolicyError(f"workflow {action} gates must be a non-empty list")
        gate_by_id: dict[str, dict] = {}
        for gate in gates:
            if not isinstance(gate, Mapping) or gate.get("kind") not in _GATE_FIELDS:
                raise GatePolicyError(f"workflow {action} has unknown gate kind")
            kind = gate["kind"]
            _exact_fields(gate, _GATE_FIELDS[kind], f"{action} {kind} gate")
            gate_id = gate["id"]
            if not isinstance(gate_id, str) or not gate_id or gate_id in gate_by_id:
                raise GatePolicyError(f"workflow {action} has invalid or duplicate gate id")
            if not isinstance(gate["requires"], list) or any(not isinstance(item, str) for item in gate["requires"]):
                raise GatePolicyError(f"gate {gate_id} requires must be a string list")
            _validate_gate_fields(action, gate)
            gate_by_id[gate_id] = gate
        for gate in gates:
            unknown = set(gate["requires"]) - set(gate_by_id)
            if unknown:
                raise GatePolicyError(f"gate {gate['id']} requires unknown gates: {sorted(unknown)}")
        _reject_cycles(action, gate_by_id)
        for gate in gates:
            gate_ancestors = _ancestors(gate["id"], gate_by_id)
            ancestor_kinds = {gate_by_id[item]["kind"] for item in gate_ancestors}
            if gate["kind"] == "approval" and "notify" not in ancestor_kinds:
                raise GatePolicyError(f"workflow {action} approval gate must depend on notify")
            if gate["kind"] == "tool" and gate["recheck"] and "approval" not in ancestor_kinds:
                raise GatePolicyError(f"workflow {action} recheck gate must depend on approval")
        executes = [gate for gate in gates if gate["kind"] == "execute"]
        if len(executes) != 1:
            raise GatePolicyError(f"workflow {action} requires exactly one execute gate")
        execute = executes[0]
        if execute["tool"] != workflow["target_tool"]:
            raise GatePolicyError(f"workflow {action} execute tool must equal target_tool")
        ancestors = _ancestors(execute["id"], gate_by_id)
        ancestor_kinds = {gate_by_id[item]["kind"] for item in ancestors}
        if "notify" not in ancestor_kinds or "approval" not in ancestor_kinds:
            raise GatePolicyError(f"workflow {action} execute path must include notify and approval gates")
        if raw["execution_enabled"]:
            approval_ids = [item for item in ancestors if gate_by_id[item]["kind"] == "approval"]
            recheck_ids = [
                item for item in ancestors
                if gate_by_id[item]["kind"] == "tool" and gate_by_id[item]["recheck"]
            ]
            for approval_id in approval_ids:
                if not any(approval_id in _ancestors(recheck_id, gate_by_id) for recheck_id in recheck_ids):
                    raise GatePolicyError(
                        f"workflow {action} enforcing execute path requires a post-approval recheck after every approval"
                    )
        if not raw["execution_enabled"] and not execute["simulation_only"]:
            raise GatePolicyError(f"workflow {action} cannot have live execute while execution is disabled")
    return _copy(raw)


def load_policy(source: str | Path | Mapping[str, Any]) -> dict:
    """Load a policy and normalize all malformed-policy errors."""
    try:
        return _load_policy(source)
    except GatePolicyError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, OSError) as error:
        raise GatePolicyError(f"malformed policy: {type(error).__name__}: {error}") from error


def _validate_schema_shape(schema: Any, action: str) -> None:
    if not isinstance(schema, Mapping) or schema.get("type") != "object":
        raise GatePolicyError(f"workflow {action} parameter_schema must be object schema")
    allowed = {"type", "additionalProperties", "required", "properties"}
    _exact_fields(schema, allowed, f"workflow {action} parameter_schema")
    if schema["additionalProperties"] is not False:
        raise GatePolicyError(f"workflow {action} parameters must reject additional properties")
    if not isinstance(schema["required"], list) or not isinstance(schema["properties"], Mapping):
        raise GatePolicyError(f"workflow {action} schema required/properties are invalid")
    if any(not isinstance(item, str) for item in schema["required"]):
        raise GatePolicyError(f"workflow {action} required parameters must be strings")
    if len(schema["required"]) != len(set(schema["required"])):
        raise GatePolicyError(f"workflow {action} required parameters must be unique")
    if not set(schema["required"]).issubset(schema["properties"]):
        raise GatePolicyError(f"workflow {action} requires undeclared parameters")
    allowed_property_fields = {"type", "minLength", "enum", "maximum", "minimum"}
    allowed_types = {"string", "boolean", "integer", "number", "object", "array"}
    for name, property_schema in schema["properties"].items():
        if not isinstance(name, str) or not isinstance(property_schema, Mapping):
            raise GatePolicyError(f"workflow {action} parameter schema is invalid")
        unknown = set(property_schema) - allowed_property_fields
        if unknown or property_schema.get("type") not in allowed_types:
            raise GatePolicyError(f"workflow {action} parameter {name} schema is invalid")
        if "minLength" in property_schema and (
            property_schema["type"] != "string"
            or type(property_schema["minLength"]) is not int
            or property_schema["minLength"] < 0
        ):
            raise GatePolicyError(f"workflow {action} parameter {name} minLength is invalid")
        if "enum" in property_schema and (
            not isinstance(property_schema["enum"], list) or not property_schema["enum"]
        ):
            raise GatePolicyError(f"workflow {action} parameter {name} enum is invalid")
        for bound in ("minimum", "maximum"):
            if bound in property_schema and (
                property_schema["type"] not in {"integer", "number"}
                or not isinstance(property_schema[bound], (int, float))
                or isinstance(property_schema[bound], bool)
                or not _is_finite_number(property_schema[bound])
            ):
                raise GatePolicyError(f"workflow {action} parameter {name} {bound} is invalid")


def _validate_comparison_spec(spec: Mapping[str, Any], context: str) -> None:
    op = spec["op"]
    value = spec.get("value")
    if op not in {"eq", "in", "lte", "gte", "truthy"}:
        raise GatePolicyError(f"{context} has unsupported comparison operator")
    if op == "in" and not isinstance(value, list):
        raise GatePolicyError(f"{context} in comparison requires a list")
    if op in {"lte", "gte"} and (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not _is_finite_number(value)
    ):
        raise GatePolicyError(f"{context} ordered comparison requires a finite number")


def _validate_gate_fields(action: str, gate: Mapping[str, Any]) -> None:
    kind = gate["kind"]
    if kind == "condition":
        if not isinstance(gate["path"], str) or not gate["path"]:
            raise GatePolicyError(f"workflow {action} condition gate is invalid")
        _validate_comparison_spec(gate, f"workflow {action} condition")
    if kind == "tool":
        if (
            not isinstance(gate["tool"], str)
            or not gate["tool"]
            or not isinstance(gate["input"], Mapping)
            or not isinstance(gate["expect"], Mapping)
        ):
            raise GatePolicyError(f"workflow {action} tool gate is invalid")
        _exact_fields(gate["expect"], {"path", "op", "value"}, f"workflow {action} expectation")
        if (
            not isinstance(gate["expect"]["path"], str)
            or not gate["expect"]["path"]
            or not isinstance(gate["recheck"], bool)
        ):
            raise GatePolicyError(f"workflow {action} tool expectation is invalid")
        _validate_comparison_spec(gate["expect"], f"workflow {action} tool expectation")
    if kind == "notify" and (
        not isinstance(gate["recipient"], str)
        or not gate["recipient"].strip()
        or not isinstance(gate["template"], str)
        or not gate["template"].strip()
    ):
        raise GatePolicyError(f"workflow {action} notification recipient/template must be non-empty")
    if kind == "approval":
        if gate["level"] not in {"human_approve_once","human_step_up"} or type(gate["ttl_seconds"]) is not int or gate["ttl_seconds"] < 1:
            raise GatePolicyError(f"workflow {action} approval gate is invalid")
    if kind == "execute" and (not isinstance(gate["tool"], str) or not isinstance(gate["simulation_only"], bool)):
        raise GatePolicyError(f"workflow {action} execute gate is invalid")


def _reject_cycles(action: str, gates: Mapping[str, dict]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(gate_id: str) -> None:
        if gate_id in visiting:
            raise GatePolicyError(f"workflow {action} gate cycle detected")
        if gate_id in visited:
            return
        visiting.add(gate_id)
        for dependency in gates[gate_id]["requires"]:
            visit(dependency)
        visiting.remove(gate_id)
        visited.add(gate_id)

    for gate_id in gates:
        visit(gate_id)


def _ancestors(gate_id: str, gates: Mapping[str, dict]) -> set[str]:
    result: set[str] = set()
    pending = list(gates[gate_id]["requires"])
    while pending:
        current = pending.pop()
        if current in result:
            continue
        result.add(current)
        pending.extend(gates[current]["requires"])
    return result


def _validate_parameters(schema: Mapping[str, Any], parameters: Any) -> dict:
    if not isinstance(parameters, Mapping):
        raise GatePolicyError("parameters must be an object")
    if any(not isinstance(name, str) for name in parameters):
        raise GatePolicyError("parameter names must be strings")
    _validate_json_value(parameters)
    properties = schema["properties"]
    unknown = set(parameters) - set(properties)
    if unknown:
        raise GatePolicyError(f"unexpected parameter(s): {', '.join(sorted(unknown))}")
    missing = set(schema["required"]) - set(parameters)
    if missing:
        raise GatePolicyError(f"missing parameter(s): {', '.join(sorted(missing))}")
    for name, value in parameters.items():
        _validate_value(name, value, properties[name])
    return _copy(parameters)


def _validate_value(name: str, value: Any, schema: Mapping[str, Any]) -> None:
    allowed = {"type", "minLength", "enum", "maximum", "minimum"}
    unknown = set(schema) - allowed
    if unknown:
        raise GatePolicyError(f"parameter {name} schema has unknown fields: {sorted(unknown)}")
    expected = schema.get("type")
    valid = {
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "integer": type(value) is int,
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": isinstance(value, Mapping),
        "array": isinstance(value, list),
    }.get(expected, False)
    if not valid:
        raise GatePolicyError(f"parameter {name} must be {expected}")
    if expected == "number" and not _is_finite_number(value):
        raise GatePolicyError(f"parameter {name} must be finite")
    if "minLength" in schema and len(value) < schema["minLength"]:
        raise GatePolicyError(f"parameter {name} is too short")
    if "enum" in schema and not any(_json_equal(value, candidate) for candidate in schema["enum"]):
        raise GatePolicyError(f"parameter {name} is not allowlisted")
    if "maximum" in schema and value > schema["maximum"]:
        raise GatePolicyError(f"parameter {name} is above maximum")
    if "minimum" in schema and value < schema["minimum"]:
        raise GatePolicyError(f"parameter {name} is below minimum")


def _resolve_path(root: Mapping[str, Any], path: str) -> Any:
    current: Any = root
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            raise GatePolicyError(f"gate path is unavailable: {path}")
        current = current[part]
    return current


def _json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is bool and type(right) is bool and left is right
    if isinstance(left, (int, float)) or isinstance(right, (int, float)):
        return (
            isinstance(left, (int, float))
            and not isinstance(left, bool)
            and isinstance(right, (int, float))
            and not isinstance(right, bool)
            and _is_finite_number(left)
            and _is_finite_number(right)
            and left == right
        )
    if isinstance(left, Mapping) or isinstance(right, Mapping):
        return (
            isinstance(left, Mapping)
            and isinstance(right, Mapping)
            and set(left) == set(right)
            and all(_json_equal(left[key], right[key]) for key in left)
        )
    if isinstance(left, list) or isinstance(right, list):
        return (
            isinstance(left, list)
            and isinstance(right, list)
            and len(left) == len(right)
            and all(_json_equal(a, b) for a, b in zip(left, right))
        )
    return type(left) is type(right) and left == right


def _compare(actual: Any, expectation: Mapping[str, Any]) -> bool:
    op = expectation["op"]
    expected = expectation.get("value")
    if op == "eq":
        return _json_equal(actual, expected)
    if op == "in":
        return isinstance(expected, list) and any(_json_equal(actual, item) for item in expected)
    if op == "lte":
        return (
            isinstance(actual, (int, float))
            and not isinstance(actual, bool)
            and _is_finite_number(actual)
            and isinstance(expected, (int, float))
            and not isinstance(expected, bool)
            and actual <= expected
        )
    if op == "gte":
        return (
            isinstance(actual, (int, float))
            and not isinstance(actual, bool)
            and _is_finite_number(actual)
            and isinstance(expected, (int, float))
            and not isinstance(expected, bool)
            and actual >= expected
        )
    if op == "truthy":
        return actual is True
    raise GatePolicyError(f"unsupported comparison operator: {op}")


def _resolve_input(value: Any, request: Mapping[str, Any]) -> Any:
    if isinstance(value, str) and value.startswith("$"):
        return _resolve_path(request, value[1:])
    if isinstance(value, Mapping):
        return {key: _resolve_input(item, request) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_input(item, request) for item in value]
    return value


def _synchronized(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapped


class GatewayEngine:
    """Deterministic state machine for semantic action workflows."""

    TERMINAL = {"blocked", "cancelled", "simulated", "executed", "failed"}
    SATISFIED = {"passed", "simulated", "approved"}

    def __init__(
        self,
        policy: Mapping[str, Any],
        *,
        registry: ToolRegistry | None = None,
        notifier: Any | None = None,
        approval_verifier: Any | None = None,
        execution_authority: ExecutionAuthority | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self.policy = load_policy(policy)
        self.registry = registry or ToolRegistry()
        self.notifier = notifier or RecordingNotifier()
        self.approval_verifier = approval_verifier or DenyAllApprovalVerifier()
        self.execution_authority = execution_authority
        self.clock = clock or (lambda: int(time.time()))
        self._requests: dict[str, dict] = {}
        self._request_workflows: dict[str, dict] = {}
        self._idempotency: dict[tuple[str, str], tuple[str, str]] = {}
        self._consumed_approval_ids: set[str] = set()
        self._consumed_notification_ids: set[str] = set()
        self._active_request_callbacks: set[str] = set()

    @contextmanager
    def _callback_scope(self, request_id: str):
        if request_id in self._active_request_callbacks:
            raise GatePolicyError("reentrant callback mutation is not allowed")
        self._active_request_callbacks.add(request_id)
        try:
            yield
        finally:
            self._active_request_callbacks.discard(request_id)

    @staticmethod
    def _principal_allowed(workflow: Mapping[str, Any], principal: str) -> bool:
        return "*" in workflow["principals"] or principal in workflow["principals"]

    def _release_terminal_workflow(self, request: Mapping[str, Any]) -> None:
        if request.get("state") in self.TERMINAL:
            self._request_workflows.pop(str(request.get("request_id")),None)

    def list_actions(self, *, principal: str | None = None) -> list[dict]:
        if principal is not None and (not isinstance(principal, str) or not principal):
            raise GatePolicyError("principal must be a non-empty string")
        return [
            {
                "action": action,
                "description": workflow["description"],
                "principals": list(workflow["principals"]),
                "target_tool": workflow["target_tool"],
                "gate_kinds": [gate["kind"] for gate in workflow["gates"]],
            }
            for action, workflow in sorted(self.policy["workflows"].items())
            if principal is None or self._principal_allowed(workflow, principal)
        ]

    def explain_action(self, action: str, *, principal: str | None = None) -> dict:
        if not isinstance(action, str) or not action:
            raise GatePolicyError("action must be a non-empty string")
        if principal is not None and (not isinstance(principal, str) or not principal):
            raise GatePolicyError("principal must be a non-empty string")
        workflow = self.policy["workflows"].get(action)
        if workflow is None:
            raise GatePolicyError(f"action is not requestable: {action}")
        if principal is not None and not self._principal_allowed(workflow, principal):
            raise GatePolicyError(f"principal is not allowed for action: {principal}")
        return {
            "action": action,
            "description": workflow["description"],
            "principals": list(workflow["principals"]),
            "target_tool": workflow["target_tool"],
            "parameter_schema": _copy(workflow["parameter_schema"]),
            "gates": _copy(workflow["gates"]),
            "execution_enabled": self.policy["execution_enabled"],
        }

    @_synchronized
    def request_action(
        self,
        *,
        action: str,
        parameters: Mapping[str, Any],
        context: Mapping[str, Any],
        trusted_context: Mapping[str, Any],
        requester: str,
        idempotency_key: str,
        minimum_control: str = "policy",
    ) -> dict:
        if not isinstance(action, str) or not action:
            raise GatePolicyError("action must be a non-empty string")
        policy_workflow = self.policy["workflows"].get(action)
        if policy_workflow is None:
            raise GatePolicyError(f"action is not requestable: {action}")
        workflow, policy_control, effective_control = _effective_workflow(policy_workflow, minimum_control)
        if not isinstance(context, Mapping):
            raise GatePolicyError("context must be an object")
        if not isinstance(trusted_context, Mapping):
            raise GatePolicyError("trusted_context must be a host-supplied object")
        if not isinstance(requester, str) or not requester or not isinstance(idempotency_key, str) or not idempotency_key:
            raise GatePolicyError("requester and idempotency_key must be non-empty")
        if not self._principal_allowed(workflow, requester):
            raise GatePolicyError(f"principal is not allowed for action: {requester}")
        normalized = _validate_parameters(workflow["parameter_schema"], parameters)
        canonical_body = {
            "version": self.policy["version"],
            "action": action,
            "parameters": normalized,
            "context": _copy(context),
            "trusted_context": _copy(trusted_context),
            "requester": requester,
            "idempotency_key": idempotency_key,
            "minimum_control": minimum_control,
            "policy_control": policy_control,
            "effective_control": effective_control,
            "workflow": workflow,
        }
        request_hash = hashlib.sha256(_canonical(canonical_body).encode("utf-8")).hexdigest()
        idempotency = (requester, idempotency_key)
        existing = self._idempotency.get(idempotency)
        if existing:
            existing_hash, request_id = existing
            if existing_hash != request_hash:
                raise GatePolicyError("idempotency key was already used for a different request")
            return self.get_request(request_id)
        request_id = "req_" + hashlib.sha256(
            f"{requester}:{idempotency_key}:{request_hash}".encode("utf-8")
        ).hexdigest()[:24]
        request = {
            "request_id": request_id,
            "request_hash": request_hash,
            "action": action,
            "parameters": normalized,
            "context": _copy(context),
            "trusted_context": _copy(trusted_context),
            "requester": requester,
            "idempotency_key": idempotency_key,
            "minimum_control": minimum_control,
            "policy_control": policy_control,
            "effective_control": effective_control,
            "state": "processing",
            "blocked_by": None,
            "notification_delivered": False,
            "execution_possible": False,
            "created_at": self.clock(),
            "gates": [
                {"id": gate["id"], "kind": gate["kind"], "status": "pending", "evidence": None}
                for gate in workflow["gates"]
            ],
        }
        self._requests[request_id] = request
        self._request_workflows[request_id] = workflow
        self._idempotency[idempotency] = (request_hash, request_id)
        self._advance(request, workflow)
        self._release_terminal_workflow(request)
        return self.get_request(request_id)

    @_synchronized
    def get_request(self, request_id: str) -> dict:
        if not isinstance(request_id, str) or not request_id:
            raise GatePolicyError("request_id must be a non-empty string")
        if request_id not in self._requests:
            raise GatePolicyError(f"request not found: {request_id}")
        public = _copy(self._requests[request_id])
        trusted = public.pop("trusted_context", {})
        public["trusted_context_hash"] = hashlib.sha256(_canonical(trusted).encode("utf-8")).hexdigest()
        return public

    @_synchronized
    def get_request_for(self, request_id: str, *, requester: str) -> dict:
        if not isinstance(request_id, str) or not request_id:
            raise GatePolicyError("request_id must be a non-empty string")
        if not isinstance(requester, str) or not requester:
            raise GatePolicyError("requester must be a non-empty string")
        request = self._requests.get(request_id)
        if request is None:
            raise GatePolicyError(f"request not found: {request_id}")
        if request["requester"] != requester:
            raise GatePolicyError("principal cannot access this request")
        return self.get_request(request_id)

    @_synchronized
    def cancel_request(self, request_id: str, *, requester: str) -> dict:
        if not isinstance(request_id, str) or not request_id:
            raise GatePolicyError("request_id must be a non-empty string")
        if not isinstance(requester, str) or not requester:
            raise GatePolicyError("requester must be a non-empty string")
        if request_id in self._active_request_callbacks:
            raise GatePolicyError("request cannot be cancelled from its active callback")
        request = self._requests.get(request_id)
        if request is None:
            raise GatePolicyError(f"request not found: {request_id}")
        if requester != request["requester"]:
            raise GatePolicyError("only the original requester may cancel")
        if request["state"] in self.TERMINAL:
            raise GatePolicyError("terminal request cannot be cancelled")
        request["state"] = "cancelled"
        self._release_terminal_workflow(request)
        return self.get_request(request_id)

    @_synchronized
    def ingest_trusted_approval(self, request_id: str, evidence: Mapping[str, Any]) -> dict:
        """Host-only API. It is intentionally not exposed as an MCP tool."""
        if not isinstance(request_id, str) or not request_id:
            raise ApprovalRejected("request_id must be a non-empty string")
        if request_id in self._active_request_callbacks:
            raise ApprovalRejected("approval cannot be ingested from its active callback")
        request = self._requests.get(request_id)
        if request is None or request["state"] != "waiting_for_approval":
            raise ApprovalRejected("request is not awaiting approval")
        if not isinstance(evidence, Mapping):
            raise ApprovalRejected("approval evidence must be an object")
        approval = next(gate for gate in request["gates"] if gate["kind"] == "approval" and gate["status"] == "waiting")
        if evidence.get("decision") != "approve":
            raise ApprovalRejected("approval decision must be approve")
        evidence_id = evidence.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            raise ApprovalRejected("approval evidence_id is missing")
        if evidence_id in self._consumed_approval_ids:
            raise ApprovalRejected("approval evidence was already consumed")
        if evidence.get("request_id") != request["request_id"]:
            raise ApprovalRejected("approval is bound to a different request ID")
        if evidence.get("request_hash") != request["request_hash"]:
            raise ApprovalRejected("approval is bound to a different request")
        if evidence.get("approval_gate_id") != approval["id"]:
            raise ApprovalRejected("approval is bound to a different approval gate")
        expires_at = evidence.get("expires_at")
        if type(expires_at) is not int or expires_at <= self.clock():
            raise ApprovalRejected("approval evidence is expired")
        workflow = self._request_workflows[request_id]
        approval_definition = next(gate for gate in workflow["gates"] if gate["id"] == approval["id"])
        if expires_at > self.clock() + approval_definition["ttl_seconds"]:
            raise ApprovalRejected("approval expiry exceeds the gate TTL")
        if not isinstance(evidence.get("actor"), str) or not evidence["actor"]:
            raise ApprovalRejected("approval actor is missing")
        assurance=evidence.get("assurance")
        if assurance not in {"ask","step_up"}:
            raise ApprovalRejected("approval assurance is missing or invalid")
        required="step_up" if approval_definition["level"]=="human_step_up" else "ask"
        if CONTROL_RANK[assurance] < CONTROL_RANK[required]:
            raise ApprovalRejected("approval assurance is below the required control")
        try:
            with self._callback_scope(request_id):
                trusted = self.approval_verifier.verify(_copy(evidence), self.get_request(request_id))
        except Exception as error:
            raise ApprovalRejected(f"approval verifier failed: {type(error).__name__}") from error
        if trusted is not True:
            raise ApprovalRejected("approval evidence is not trusted")
        self._consumed_approval_ids.add(evidence_id)
        approval["status"] = "approved"
        approval["evidence"] = {
            "evidence_id": evidence_id,
            "approval_gate_id": approval["id"],
            "request_id": request["request_id"],
            "actor": evidence["actor"],
            "decision": "approve",
            "assurance": assurance,
            "request_hash": request["request_hash"],
            "expires_at": expires_at,
            "consumed_at": self.clock(),
        }
        request["state"] = "processing"
        self._advance(request, workflow)
        self._release_terminal_workflow(request)
        return self.get_request(request_id)

    def _advance(self, request: dict, workflow: Mapping[str, Any]) -> None:
        definitions = {gate["id"]: gate for gate in workflow["gates"]}
        runtime = {gate["id"]: gate for gate in request["gates"]}
        while request["state"] == "processing":
            progressed = False
            for definition in workflow["gates"]:
                gate = runtime[definition["id"]]
                if gate["status"] != "pending":
                    continue
                dependencies = [runtime[item]["status"] for item in definition["requires"]]
                if not all(status in self.SATISFIED for status in dependencies):
                    continue
                progressed = True
                kind = definition["kind"]
                if kind == "schema":
                    gate["status"] = "passed"
                    gate["evidence"] = {"normalized": True}
                elif kind == "condition":
                    try:
                        actual = _resolve_path(request, definition["path"])
                        matches = _compare(actual, definition)
                    except Exception as error:
                        self._block(request, gate, {"reason": "condition_unavailable", "error_type": type(error).__name__})
                        return
                    if not matches:
                        self._block(request, gate, {"actual": actual})
                        return
                    gate["status"] = "passed"
                    gate["evidence"] = {"actual": actual}
                elif kind == "tool":
                    try:
                        arguments = _resolve_input(definition["input"], request)
                        with self._callback_scope(request["request_id"]):
                            result = self.registry.call_read(definition["tool"], arguments)
                        actual = _resolve_path(result, definition["expect"]["path"])
                        matches = _compare(actual, definition["expect"])
                    except Exception as error:
                        gate["status"] = "failed"
                        gate["evidence"] = {
                            "tool": definition["tool"],
                            "error_type": type(error).__name__,
                            "retry_allowed": False,
                        }
                        request["state"] = "failed"
                        request["blocked_by"] = gate["id"]
                        return
                    if not matches:
                        self._block(request, gate, {"tool": definition["tool"], "result": result})
                        return
                    gate["status"] = "passed"
                    gate["evidence"] = {"tool": definition["tool"], "result": result, "checked_at": self.clock()}
                elif kind == "notify":
                    try:
                        with self._callback_scope(request["request_id"]):
                            event = self.notifier.notify(self.get_request(request["request_id"]), definition)
                        if not isinstance(event, Mapping):
                            raise GatePolicyError("notifier must return an object")
                        event = _copy(event)
                    except Exception as error:
                        gate["status"] = "failed"
                        gate["evidence"] = {
                            "error_type": type(error).__name__,
                            "retry_allowed": False,
                        }
                        request["state"] = "failed"
                        request["blocked_by"] = gate["id"]
                        return
                    delivered = event.get("delivered") is True
                    gate["evidence"] = event
                    request["notification_delivered"] = delivered
                    notification_id = event.get("notification_id")
                    template_hash = hashlib.sha256(definition["template"].encode("utf-8")).hexdigest()
                    bound = (
                        event.get("request_id") == request["request_id"]
                        and event.get("request_hash") == request["request_hash"]
                        and event.get("notification_gate_id") == gate["id"]
                        and event.get("recipient") == definition["recipient"]
                        and event.get("template_hash") == template_hash
                        and isinstance(notification_id, str)
                        and bool(notification_id)
                        and notification_id not in self._consumed_notification_ids
                    )
                    if self.policy["mode"] == "enforcing":
                        delivered_at = event.get("delivered_at")
                        bound = (
                            bound
                            and type(delivered_at) is int
                            and request["created_at"] <= delivered_at <= self.clock()
                        )
                    if not bound:
                        self._block(request, gate, gate["evidence"])
                        return
                    if self.policy["mode"] == "enforcing" and not delivered:
                        self._block(request, gate, gate["evidence"])
                        return
                    self._consumed_notification_ids.add(str(notification_id))
                    gate["status"] = "passed" if delivered else "simulated"
                elif kind == "approval":
                    gate["status"] = "waiting"
                    gate["evidence"] = {
                        "level": definition["level"],
                        "ttl_seconds": definition["ttl_seconds"],
                        "request_hash": request["request_hash"],
                    }
                    request["state"] = "waiting_for_approval"
                    return
                elif kind == "execute":
                    approval_ids = [
                        gate_id for gate_id in _ancestors(definition["id"], definitions)
                        if definitions[gate_id]["kind"] == "approval"
                    ]
                    if any(
                        type(runtime[gate_id]["evidence"].get("expires_at")) is not int
                        or runtime[gate_id]["evidence"]["expires_at"] <= self.clock()
                        for gate_id in approval_ids
                    ):
                        self._block(request, gate, {"reason": "approval_expired"})
                        return
                    if definition["simulation_only"] or not self.policy["execution_enabled"]:
                        gate["status"] = "simulated"
                        gate["evidence"] = {"tool": definition["tool"], "arguments_hash": hashlib.sha256(_canonical(request["parameters"]).encode("utf-8")).hexdigest()}
                        request["would_call"] = {"tool": definition["tool"], "arguments": _copy(request["parameters"])}
                        request["state"] = "simulated"
                        request["execution_possible"] = False
                        return
                    if self.execution_authority is None:
                        gate["status"] = "failed"
                        gate["evidence"] = {
                            "tool": definition["tool"],
                            "error_type": "MissingExecutionAuthority",
                            "retry_allowed": False,
                        }
                        request["state"] = "failed"
                        request["execution_possible"] = False
                        return
                    try:
                        with self._callback_scope(request["request_id"]):
                            result = self.registry.call_target(definition["tool"], request["parameters"])
                    except Exception as error:
                        gate["status"] = "failed"
                        gate["evidence"] = {
                            "tool": definition["tool"],
                            "error_type": type(error).__name__,
                            "retry_allowed": False,
                        }
                        request["state"] = "failed"
                        request["execution_possible"] = False
                        return
                    gate["status"] = "passed"
                    gate["evidence"] = {"tool": definition["tool"], "result": result, "authority": self.execution_authority.issuer}
                    request["state"] = "executed"
                    request["execution_possible"] = True
                    request["execution_result"] = result
                    return
            if not progressed:
                unresolved = [gate_id for gate_id, gate in runtime.items() if gate["status"] == "pending"]
                if unresolved:
                    raise GatePolicyError(f"gate graph made no progress: {unresolved}")
                return

    @staticmethod
    def _block(request: dict, gate: dict, evidence: dict) -> None:
        gate["status"] = "blocked"
        gate["evidence"] = _copy(evidence)
        request["state"] = "blocked"
        request["blocked_by"] = gate["id"]
