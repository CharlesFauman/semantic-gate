"""Dependency-free MCP stdio facade for Semantic Gate."""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any, BinaryIO, Mapping, TextIO

from . import __version__
from .engine import (
    DenyAllApprovalVerifier,
    GatePolicyError,
    GatewayEngine,
    RecordingNotifier,
    ToolRegistry,
    load_policy,
)


SUPPORTED_PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18"}
DEFAULT_PROTOCOL = "2025-03-26"
MCP_NEW = "new"
MCP_INITIALIZE_RESPONDED = "initialize_responded"
MCP_READY = "ready"


def _reject_nonfinite_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000
MAX_JSON_COLLECTION_ITEMS = 10_000
MAX_JSON_STRING_CHARS = 65_536
MAX_JSON_INTEGER = 2**63 - 1
MAX_JSON_RPC_ID_CHARS = 256
MAX_JSON_RPC_LINE_CHARS = 1_048_576


def _valid_request_id(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return len(value) <= MAX_JSON_RPC_ID_CHARS
    if type(value) is int:
        return -MAX_JSON_INTEGER - 1 <= value <= MAX_JSON_INTEGER
    if type(value) is not float:
        return False
    return math.isfinite(value) and abs(value) <= 2**53


def _strict_json_copy(value: Any) -> Any:
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
    try:
        return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))
    except (TypeError, ValueError) as error:
        raise GatePolicyError(f"value must be JSON-serializable: {error}") from error


def _object(properties: dict | None = None, required: list[str] | None = None) -> dict:
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
        "additionalProperties": False,
    }


TOOLS = [
    {
        "name": "list_actions",
        "description": "List semantic actions that this gateway will accept as proposals.",
        "inputSchema": _object(),
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    },
    {
        "name": "explain_action",
        "description": "Show the exact parameter schema and deterministic gate graph for one action.",
        "inputSchema": _object({"action": {"type": "string", "minLength": 1}}, ["action"]),
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    },
    {
        "name": "request_action",
        "description": "Propose an action. Semantic Gate decides required control; caller may set only a stricter floor. This tool cannot approve or execute.",
        "inputSchema": _object({
            "action": {"type": "string", "minLength": 1},
            "parameters": {"type": "object"},
            "context": {"type": "object"},
            "idempotency_key": {"type": "string", "minLength": 1},
            "minimum_control": {"type":"string","enum":["policy","ask","step_up"],"default":"policy"},
        }, ["action", "parameters", "context", "idempotency_key"]),
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "get_request",
        "description": "Read current gate state and evidence for a request.",
        "inputSchema": _object({"request_id": {"type": "string", "minLength": 1}}, ["request_id"]),
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    },
    {
        "name": "cancel_request",
        "description": "Restrictively cancel a pending request. Cancellation never executes the target.",
        "inputSchema": _object({
            "request_id": {"type": "string", "minLength": 1},
        }, ["request_id"]),
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
]


class SemanticGateMCP:
    def __init__(self, engine: GatewayEngine, *, principal: str, trusted_context: Mapping[str, Any]) -> None:
        if not isinstance(principal, str) or not principal.strip():
            raise GatePolicyError("MCP principal must be non-empty")
        if not isinstance(trusted_context, Mapping):
            raise GatePolicyError("MCP trusted_context must be an object")
        self.engine = engine
        self.principal = principal
        self.trusted_context = _strict_json_copy(trusted_context)
        self._mcp_state = MCP_NEW

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> dict:
        if not isinstance(arguments, Mapping):
            raise GatePolicyError("tool arguments must be an object")
        if name == "list_actions":
            _require_args(arguments, set(), set())
            result = self.engine.list_actions(principal=self.principal)
        elif name == "explain_action":
            _require_args(arguments, {"action"}, {"action"})
            result = self.engine.explain_action(arguments["action"], principal=self.principal)
        elif name == "request_action":
            required = {"action", "parameters", "context", "idempotency_key"}
            _require_args(arguments, required | {"minimum_control"}, required)
            result = self.engine.request_action(
                action=arguments["action"],
                parameters=arguments["parameters"],
                context=arguments["context"],
                trusted_context=self.trusted_context,
                requester=self.principal,
                idempotency_key=arguments["idempotency_key"],
                minimum_control=arguments.get("minimum_control","policy"),
            )
        elif name == "get_request":
            _require_args(arguments, {"request_id"}, {"request_id"})
            result = self.engine.get_request_for(arguments["request_id"], requester=self.principal)
        elif name == "cancel_request":
            _require_args(arguments, {"request_id"}, {"request_id"})
            result = self.engine.cancel_request(arguments["request_id"], requester=self.principal)
        else:
            raise GatePolicyError(f"unknown MCP tool: {name}")
        return {
            "content": [{"type": "text", "text": json.dumps(result, sort_keys=True, allow_nan=False)}],
            "structuredContent": result,
            "isError": False,
        }

    def serve(self, incoming: TextIO, outgoing: TextIO) -> None:
        self._mcp_state = MCP_NEW
        while True:
            raw_line = incoming.readline(MAX_JSON_RPC_LINE_CHARS + 1)
            if raw_line == "":
                break
            oversized = (
                len(raw_line) > MAX_JSON_RPC_LINE_CHARS
                or len(raw_line.encode("utf-8")) > MAX_JSON_RPC_LINE_CHARS
            )
            if oversized:
                while raw_line and not raw_line.endswith("\n"):
                    raw_line = incoming.readline(MAX_JSON_RPC_LINE_CHARS + 1)
                response = _error(None, -32700, "parse error: message is too large")
            elif not raw_line.strip():
                continue
            else:
                try:
                    message = json.loads(raw_line, parse_constant=_reject_nonfinite_constant)
                    response = process_message(self, message, enforce_lifecycle=True)
                except (json.JSONDecodeError, TypeError, ValueError, OverflowError, RecursionError) as error:
                    response = _error(None, -32700, f"parse error: {error}")
            if response is not None:
                try:
                    encoded = json.dumps(response, separators=(",", ":"), allow_nan=False)
                except (TypeError, ValueError, OverflowError, RecursionError):
                    encoded = json.dumps(_error(response.get("id"), -32603, "non-JSON result"), separators=(",", ":"))
                outgoing.write(encoded + "\n")
                outgoing.flush()

    def serve_binary(self, incoming: BinaryIO, outgoing: BinaryIO) -> None:
        """Serve stdio bytes while containing malformed UTF-8 as parse errors."""
        self._mcp_state = MCP_NEW
        while True:
            raw_line = incoming.readline(MAX_JSON_RPC_LINE_CHARS + 1)
            if raw_line == b"":
                break
            oversized = len(raw_line) > MAX_JSON_RPC_LINE_CHARS
            if oversized:
                while raw_line and not raw_line.endswith(b"\n"):
                    raw_line = incoming.readline(MAX_JSON_RPC_LINE_CHARS + 1)
                response = _error(None, -32700, "parse error: message is too large")
            else:
                try:
                    decoded = raw_line.decode("utf-8", errors="strict")
                    if not decoded.strip():
                        continue
                    message = json.loads(decoded, parse_constant=_reject_nonfinite_constant)
                    response = process_message(self, message, enforce_lifecycle=True)
                except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, OverflowError, RecursionError) as error:
                    response = _error(None, -32700, f"parse error: {type(error).__name__}")
            if response is not None:
                try:
                    encoded = json.dumps(response, separators=(",", ":"), allow_nan=False)
                except (TypeError, ValueError, OverflowError, RecursionError):
                    encoded = json.dumps(_error(response.get("id"), -32603, "non-JSON result"), separators=(",", ":"))
                outgoing.write((encoded + "\n").encode("utf-8"))
                outgoing.flush()


def _require_args(arguments: Mapping[str, Any], allowed: set[str], required: set[str]) -> None:
    if any(not isinstance(key, str) for key in arguments):
        raise GatePolicyError("argument names must be strings")
    unknown = set(arguments) - allowed
    missing = required - set(arguments)
    if unknown:
        raise GatePolicyError(f"unknown argument(s): {', '.join(sorted(unknown))}")
    if missing:
        raise GatePolicyError(f"missing argument(s): {', '.join(sorted(missing))}")


def build_server(
    policy_path: str | Path,
    *,
    registry: ToolRegistry | None = None,
    notifier: Any | None = None,
    principal: str,
    trusted_context: Mapping[str, Any] | None = None,
) -> SemanticGateMCP:
    """Build a safe MCP server. Approval verifier denies all; no execution authority is installed."""
    policy = load_policy(policy_path)
    engine = GatewayEngine(
        policy,
        registry=registry or ToolRegistry(),
        notifier=notifier or RecordingNotifier(),
        approval_verifier=DenyAllApprovalVerifier(),
        execution_authority=None,
    )
    return SemanticGateMCP(engine, principal=principal, trusted_context=trusted_context or {})


def process_message(server: SemanticGateMCP, message: Mapping[str, Any], *, enforce_lifecycle: bool = False) -> dict | None:
    if not isinstance(message, Mapping):
        return _error(None, -32600, "invalid request")
    try:
        message = _strict_json_copy(message)
    except GatePolicyError as error:
        return _error(None, -32600, f"invalid request: {error}")
    if message.get("jsonrpc") != "2.0":
        candidate = message.get("id")
        return _error(candidate if _valid_request_id(candidate) else None, -32600, "invalid request")
    has_id = "id" in message
    request_id = message.get("id")
    if has_id and not _valid_request_id(request_id):
        return _error(None, -32600, "invalid request id")
    method = message.get("method")
    if not isinstance(method, str):
        return _error(request_id if has_id else None, -32600, "method must be a string") if has_id else None
    params = message.get("params", {})
    if method == "notifications/initialized" and not has_id:
        if enforce_lifecycle and server._mcp_state == MCP_INITIALIZE_RESPONDED:
            server._mcp_state = MCP_READY
        return None
    if not has_id:
        return None
    try:
        if method == "initialize":
            if enforce_lifecycle and server._mcp_state != MCP_NEW:
                return _error(request_id, -32600, "initialize already processed")
            if not isinstance(params, Mapping):
                raise GatePolicyError("initialize params must be an object")
            _require_args(
                params,
                {"protocolVersion", "capabilities", "clientInfo", "_meta"},
                {"protocolVersion"},
            )
            requested = params.get("protocolVersion", DEFAULT_PROTOCOL)
            if not isinstance(requested, str):
                raise GatePolicyError("initialize protocolVersion must be a string")
            if "capabilities" in params and not isinstance(params["capabilities"], Mapping):
                raise GatePolicyError("initialize capabilities must be an object")
            if "clientInfo" in params and not isinstance(params["clientInfo"], Mapping):
                raise GatePolicyError("initialize clientInfo must be an object")
            if "_meta" in params and not isinstance(params["_meta"], Mapping):
                raise GatePolicyError("initialize _meta must be an object")
            _strict_json_copy(params)
            protocol = requested if requested in SUPPORTED_PROTOCOLS else DEFAULT_PROTOCOL
            result = {
                "protocolVersion": protocol,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "semantic-gate", "version": __version__},
                "instructions": "Propose actions through request_action. Human approval and target execution are not agent-callable MCP tools.",
            }
            if enforce_lifecycle:
                server._mcp_state = MCP_INITIALIZE_RESPONDED
        elif method == "ping":
            if not isinstance(params, Mapping) or params:
                raise GatePolicyError("ping params must be an empty object")
            result = {}
        elif method == "tools/list":
            if enforce_lifecycle and server._mcp_state != MCP_READY:
                return _error(request_id, -32002, "server not initialized")
            if not isinstance(params, Mapping) or params:
                raise GatePolicyError("tools/list params must be an empty object")
            result = {"tools": TOOLS}
        elif method == "tools/call":
            if enforce_lifecycle and server._mcp_state != MCP_READY:
                return _error(request_id, -32002, "server not initialized")
            if not isinstance(params, Mapping):
                raise GatePolicyError("tools/call params must be an object")
            _require_args(params, {"name", "arguments"}, {"name", "arguments"})
            result = server.call_tool(params["name"], params["arguments"])
        else:
            return _error(request_id, -32601, f"method not found: {method}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except GatePolicyError as error:
        return _error(request_id, -32602, str(error))
    except Exception:
        return _error(request_id, -32603, "internal error")


def _error(request_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Semantic Gate as an MCP stdio server")
    parser.add_argument("--policy", required=True, help="Path to a validated workflow policy JSON file")
    parser.add_argument("--principal", required=True, help="Host-assigned identity for this MCP process")
    parser.add_argument("--trusted-context-json", default="{}", help="Host-supplied JSON object; never agent-controlled")
    args = parser.parse_args(argv)
    try:
        trusted_context = json.loads(args.trusted_context_json, parse_constant=_reject_nonfinite_constant)
    except (json.JSONDecodeError, ValueError) as error:
        parser.error(f"invalid --trusted-context-json: {error}")
    if not isinstance(trusted_context, dict):
        parser.error("--trusted-context-json must decode to an object")
    server = build_server(args.policy, principal=args.principal, trusted_context=trusted_context)
    server.serve_binary(sys.stdin.buffer, sys.stdout.buffer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
