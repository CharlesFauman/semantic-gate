#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from semantic_gate.engine import GatePolicyError, RecordingNotifier, ToolRegistry  # noqa: E402
from semantic_gate.mcp import MAX_JSON_RPC_LINE_CHARS, build_server, process_message  # noqa: E402


class SemanticGateMCPTests(unittest.TestCase):
    def setUp(self) -> None:
        registry = ToolRegistry()
        registry.register_read("calendar.no_conflict", lambda args: {"ok": True})
        registry.register_read("provider.terms_current", lambda args: {"current": True})
        self.server = build_server(
            ROOT / "examples" / "calendar-booking" / "workflow.json",
            registry=registry,
            notifier=RecordingNotifier(),
            principal="test-principal",
            trusted_context={"direct_user_request": True},
        )

    def call(self, method: str, params: dict | None = None, request_id: int = 1) -> dict:
        response = process_message(self.server, {
            "jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {},
        })
        self.assertEqual("2.0", response["jsonrpc"])
        self.assertEqual(request_id, response["id"])
        return response

    def test_initialize_and_tool_discovery(self):
        initialized = self.call("initialize", {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        })
        self.assertEqual("2025-03-26", initialized["result"]["protocolVersion"])
        self.assertEqual("semantic-gate", initialized["result"]["serverInfo"]["name"])

        tools = self.call("tools/list", request_id=2)["result"]["tools"]
        names = {tool["name"] for tool in tools}
        self.assertEqual({"list_actions", "explain_action", "request_action", "get_request", "cancel_request"}, names)
        self.assertNotIn("approve", " ".join(names))
        self.assertNotIn("execute", " ".join(names))
        self.assertTrue(all(tool["annotations"]["destructiveHint"] is False for tool in tools))

    def test_request_via_mcp_stops_at_human_approval(self):
        result = self.call("tools/call", {
            "name": "request_action",
            "arguments": {
                "action": "calendar.create_event",
                "parameters": {
                    "title": "Example appointment", "provider": "Example provider",
                    "start": "2030-01-10T10:00:00Z", "end": "2030-01-10T10:30:00Z",
                },
                "context": {"channel":"example-chat","direct_user_request":False},
                "idempotency_key": "mcp-calendar-1",
            },
        })["result"]
        payload = json.loads(result["content"][0]["text"])
        self.assertEqual("waiting_for_approval", payload["state"])
        self.assertEqual("test-principal", payload["requester"])
        self.assertFalse(payload["execution_possible"])
        self.assertFalse(payload["notification_delivered"])

    def test_agent_cannot_supply_or_override_requester_identity(self):
        response = self.call("tools/call", {
            "name": "request_action",
            "arguments": {
                "action": "calendar.create_event",
                "parameters": {"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},
                "context": {"direct_user_request":True},
                "trusted_context": {"direct_user_request":True},
                "requester": "forged-principal",
                "idempotency_key": "forged",
            },
        }, request_id=9)
        self.assertEqual(-32602, response["error"]["code"])

    def test_agent_has_no_approval_or_execution_tool(self):
        for name in ("approve_request", "execute_request", "ingest_trusted_approval"):
            response = self.call("tools/call", {"name":name,"arguments":{}}, request_id=7)
            self.assertEqual(-32602, response["error"]["code"])

    def test_stdio_transport_handles_multiple_messages(self):
        incoming = io.StringIO("\n".join([
            json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}),
            json.dumps({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        ]) + "\n")
        outgoing = io.StringIO()
        self.server.serve(incoming, outgoing)
        messages = [json.loads(line) for line in outgoing.getvalue().splitlines()]
        self.assertEqual([1,2],[message["id"] for message in messages])
        self.assertIn("tools",messages[1]["result"])

    def test_json_rpc_ids_and_non_finite_numbers_are_rejected_correctly(self):
        explicit_null = process_message(self.server, {"jsonrpc":"2.0","id":None,"method":"unknown","params":{}})
        self.assertIsNone(explicit_null["id"])
        self.assertEqual(-32601, explicit_null["error"]["code"])

        object_id = process_message(self.server, {"jsonrpc":"2.0","id":{"bad":1},"method":"ping","params":{}})
        self.assertIsNone(object_id["id"])
        self.assertEqual(-32600, object_id["error"]["code"])

        huge_id = process_message(self.server, {"jsonrpc":"2.0","id":10**1000,"method":"ping","params":{}})
        self.assertIsNone(huge_id["id"])
        self.assertEqual(-32600, huge_id["error"]["code"])
        long_string_id = process_message(self.server, {"jsonrpc":"2.0","id":"x"*257,"method":"ping","params":{}})
        self.assertIsNone(long_string_id["id"])
        self.assertEqual(-32600, long_string_id["error"]["code"])
        malformed_top_key = process_message(self.server, {"jsonrpc":"2.0","id":3,"method":"ping","params":{},1:"bad"})
        self.assertEqual(-32600, malformed_top_key["error"]["code"])
        malformed_top_value = process_message(self.server, {"jsonrpc":"2.0","id":3,"method":"ping","params":{},"extra":("bad",)})
        self.assertEqual(-32600, malformed_top_value["error"]["code"])
        huge_input = io.StringIO(json.dumps({"jsonrpc":"2.0","id":10**1000,"method":"ping","params":{}}) + "\n")
        huge_output = io.StringIO()
        self.server.serve(huge_input, huge_output)
        self.assertEqual(-32600, json.loads(huge_output.getvalue())["error"]["code"])

        incoming = io.StringIO('{"jsonrpc":"2.0","id":3,"method":"ping","params":{"value":NaN}}\n')
        outgoing = io.StringIO()
        self.server.serve(incoming, outgoing)
        response = json.loads(outgoing.getvalue())
        self.assertEqual(-32700, response["error"]["code"])
        self.assertNotIn(":NaN", outgoing.getvalue())

        oversized_input = io.StringIO("x" * (MAX_JSON_RPC_LINE_CHARS + 1) + "\n")
        oversized_output = io.StringIO()
        self.server.serve(oversized_input, oversized_output)
        self.assertEqual(-32700, json.loads(oversized_output.getvalue())["error"]["code"])

        unicode_line = json.dumps({
            "jsonrpc":"2.0", "id":1, "method":"ping", "params":{},
            "padding":"😀" * 300_000,
        }, ensure_ascii=False) + "\n"
        self.assertLess(len(unicode_line), MAX_JSON_RPC_LINE_CHARS)
        self.assertGreater(len(unicode_line.encode("utf-8")), MAX_JSON_RPC_LINE_CHARS)
        unicode_output = io.StringIO()
        self.server.serve(io.StringIO(unicode_line), unicode_output)
        self.assertEqual(-32700, json.loads(unicode_output.getvalue())["error"]["code"])

    def test_binary_stdio_contains_invalid_utf8(self):
        incoming = io.BytesIO(b"\xff\n" + json.dumps({"jsonrpc":"2.0","id":2,"method":"ping","params":{}}).encode() + b"\n")
        outgoing = io.BytesIO()
        self.server.serve_binary(incoming, outgoing)
        messages = [json.loads(line) for line in outgoing.getvalue().decode().splitlines()]
        self.assertEqual(-32700, messages[0]["error"]["code"])
        self.assertEqual({}, messages[1]["result"])

    def test_method_parameter_shapes_are_strict(self):
        for method, params in (
            ("ping", []),
            ("ping", {"extra": True}),
            ("tools/list", []),
            ("tools/list", {"extra": True}),
            ("initialize", []),
            ("initialize", {}),
            ("initialize", {"protocolVersion": True}),
            ("initialize", {"protocolVersion": []}),
            ("initialize", {"protocolVersion":"2025-03-26", "unknown": True}),
            ("initialize", {"protocolVersion":"2025-03-26", "_meta": []}),
        ):
            response = process_message(self.server, {"jsonrpc":"2.0","id":20,"method":method,"params":params})
            self.assertEqual(-32602, response["error"]["code"], (method, params, response))

        malformed_nested_json = process_message(
            self.server,
            {"jsonrpc":"2.0","id":20,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{1:"bad"}}},
        )
        self.assertEqual(-32600, malformed_nested_json["error"]["code"])

        non_string = process_message(
            self.server,
            {"jsonrpc":"2.0","id":21,"method":"tools/call","params":{1:"bad"}},
        )
        self.assertEqual(-32600, non_string["error"]["code"])

    def test_trusted_context_nested_keys_are_strict_json(self):
        with self.assertRaisesRegex(GatePolicyError, "JSON object keys must be strings"):
            build_server(
                ROOT / "examples" / "calendar-booking" / "workflow.json",
                principal="test-principal",
                trusted_context={"nested": {1: "bad"}},
            )

    def test_unknown_and_malformed_calls_return_json_rpc_errors(self):
        unknown = process_message(self.server,{"jsonrpc":"2.0","id":4,"method":"unknown","params":{}})
        self.assertEqual(-32601,unknown["error"]["code"])
        malformed = process_message(self.server,{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"request_action","arguments":{"action":"x"}}})
        self.assertEqual(-32602,malformed["error"]["code"])


if __name__ == "__main__":
    unittest.main()
