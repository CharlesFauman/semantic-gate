#!/usr/bin/env python3
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

from semantic_gate.auth import CapabilityAuthority
from semantic_gate.autoapproval import AutoApprovalPolicy
from semantic_gate.catalog import build_policy
from semantic_gate.controller import GateControl
from semantic_gate.coordinator import CoreBackend
from semantic_gate.credentials import CredentialRegistry
from semantic_gate.httpd import build_parser, compose, make_http_server
from semantic_gate.server import SemanticGateApplication
from semantic_gate.storage import Ledger
from tests.test_server import SemanticGateApplicationTests

CATALOG = {"version": 1, "actions": {
    "code.edit_file": {"domain": "code", "risk": "R1", "effect": "write", "summary": "Apply one reviewed patch", "approval": "separate_confirmation", "gate_class": "automatic"},
    "communication.send": {"domain": "communication", "risk": "R2", "effect": "external_write", "summary": "Send a message to a person", "approval": "separate_confirmation", "gate_class": "human_communication"},
    "purchase.place_order": {"domain": "purchase", "risk": "R3", "effect": "external_write", "summary": "Place an order", "approval": "step_up", "gate_class": "human_spending"},
    "system.shell.execute": {"domain": "system", "risk": "R4", "effect": "prohibited", "summary": "Shell", "approval": "prohibited", "gate_class": "prohibited"},
}}
DOCUMENT = {"version": 1, "enabled": True, "rules": [], "global_simulation_rule": {
    "rule_id": "rule-global-simulation", "version": 1,
    "human_gate_classes": ["human_communication", "human_spending"],
    "requesters": ["agent"], "nodes": ["node-example-1"],
    "expires_at": 4102444800, "review_by": 4102358400}}


class HTTPServerTests(SemanticGateApplicationTests):
    def test_real_http_health_and_size_limit(self):
        server=make_http_server(self.app,"127.0.0.1",0)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            with urlopen(f"http://127.0.0.1:{server.server_port}/health",timeout=2) as response:
                self.assertEqual("ok",json.load(response)["status"])
        finally:
            server.shutdown(); server.server_close(); thread.join(2)


class SynchronousAutomaticTransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        principals = {"principals": {
            "agent": {"role": "agent", "enabled": True, "node": "node-example-1"},
            "control-panel": {"role": "admin", "enabled": True, "node": "node-control"},
        }}
        for name, value in (("catalog.json", CATALOG), ("principals.json", principals),
                            ("credentials.json", {"credentials": {}}), ("auto-approval.json", DOCUMENT)):
            (self.root / name).write_text(json.dumps(value))
        args = build_parser().parse_args([
            "--bind", "127.0.0.1", "--catalog", str(self.root / "catalog.json"),
            "--principals", str(self.root / "principals.json"), "--credentials", str(self.root / "credentials.json"),
            "--database", str(self.root / "ledger.sqlite3"), "--origin", "https://control.example",
            "--auto-approval", str(self.root / "auto-approval.json")])
        self.app, self.ledger = compose(args, master_key=bytes.fromhex("33" * 32),
            approval_key=bytes.fromhex("22" * 32), admin_password="correct horse battery staple", clock=lambda: 100)
        self.server = make_http_server(self.app, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.token = self.app.authority.token_for("agent")

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)
        self.ledger.close(); self.tmp.cleanup()

    def post(self, path, payload):
        request = Request(self.base + path, data=json.dumps(payload).encode(), method="POST",
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        with urlopen(request, timeout=2) as response:
            return response.status, json.load(response)

    @staticmethod
    def payload(action, key):
        return {"action": action,
            "parameters": {"summary": "Simulate the catalogued action", "target": "example-target", "details": {}},
            "context": {"node": "caller-cannot-select-node"}, "idempotency_key": key}

    def assert_terminal_automatic(self, request):
        self.assertEqual("simulated", request["state"], request.get("auto_approval"))
        self.assertFalse(request["execution_possible"])
        auto = request["auto_approval"]
        self.assertEqual(("rule-global-simulation", 1), (auto["rule_id"], auto["rule_version"]))
        self.assertFalse(auto["authorizes_execution"])
        self.assertEqual((request["request_id"], request["request_hash"]), (auto["request_id"], auto["request_hash"]))

    def test_mcp_automatic_is_terminal_in_the_same_call_and_exclusions_wait(self):
        def call(action, key):
            status, body = self.post("/mcp", {"jsonrpc": "2.0", "id": key, "method": "tools/call", "params": {
                "name": "request_action", "arguments": self.payload(action, key)}})
            self.assertEqual(200, status); self.assertNotIn("error", body)
            return body["result"]["structuredContent"]
        self.assert_terminal_automatic(call("code.edit_file", "mcp-auto"))
        for action in ("communication.send", "purchase.place_order"):
            excluded = call(action, "mcp-" + action)
            self.assertEqual("waiting_for_approval", excluded["state"])
            self.assertFalse(excluded["auto_approval"]["matched"])

    def test_http_automatic_is_terminal_in_the_same_call_and_exclusions_wait(self):
        status, automatic = self.post("/api/v1/requests", self.payload("code.edit_file", "http-auto"))
        self.assertEqual(201, status); self.assert_terminal_automatic(automatic)
        for action in ("communication.send", "purchase.place_order"):
            status, excluded = self.post("/api/v1/requests", self.payload(action, "http-" + action))
            self.assertEqual(201, status); self.assertEqual("waiting_for_approval", excluded["state"])

    def test_idempotent_and_concurrent_replays_preserve_terminal_policy_evidence(self):
        payload = self.payload("code.edit_file", "replayed-auto")
        first = self.post("/api/v1/requests", payload)[1]
        second = self.post("/api/v1/requests", payload)[1]
        self.assert_terminal_automatic(first); self.assert_terminal_automatic(second)
        self.assertEqual(first["auto_approval"], second["auto_approval"])
        self.assertEqual(["requested", "auto_approved"],
                         [item["event"] for item in self.ledger.audit_events(first["request_id"])])

        concurrent_payload = self.payload("code.edit_file", "concurrent-auto")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.post("/api/v1/requests", concurrent_payload)[1], range(2)))
        for result in results:
            self.assert_terminal_automatic(result)
        request_id = results[0]["request_id"]
        self.assertEqual(["requested", "auto_approved"],
                         [item["event"] for item in self.ledger.audit_events(request_id)])

    def test_caller_node_cannot_override_the_authenticated_principal_binding(self):
        self.app.principal_contexts["agent"]["node"] = "node-other"
        status, request = self.post("/api/v1/requests", self.payload("code.edit_file", "wrong-host-node"))
        self.assertEqual(201, status)
        self.assertEqual("waiting_for_approval", request["state"])
        self.assertFalse(request["auto_approval"]["matched"])
        self.assertEqual("node_not_declared", request["auto_approval"]["reason_code"])

    def test_notifier_outage_is_not_called_and_cannot_fail_the_automatic_decision(self):
        class OutageNotifier:
            def __init__(self): self.calls = 0
            def notify(self, request, gate):
                self.calls += 1
                raise RuntimeError("provider unavailable")
        principals = {"agent": {"role": "agent", "enabled": True, "node": "node-example-1"},
            "control-panel": {"role": "admin", "enabled": True, "node": "node-control"}}
        notifier = OutageNotifier()
        backend = CoreBackend(build_policy(CATALOG, principals), approval_key=bytes.fromhex("22" * 32), clock=lambda: 100,
            notifier=notifier, auto_approval=AutoApprovalPolicy(DOCUMENT), catalog=CATALOG)
        ledger = Ledger(self.root / "outage.sqlite3")
        app = SemanticGateApplication(GateControl(backend, ledger, clock=lambda: 100),
            CapabilityAuthority(bytes.fromhex("33" * 32), principals), CredentialRegistry(self.root / "credentials.json"),
            catalog=CATALOG, admin_password="correct horse battery staple", admin_principal_id="control-panel",
            origins=["https://control.example"], clock=lambda: 100, principal_contexts=principals)
        server = make_http_server(app, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            token = app.authority.token_for("agent")
            request = Request(f"http://127.0.0.1:{server.server_port}/api/v1/requests",
                data=json.dumps(self.payload("code.edit_file", "outage-auto")).encode(), method="POST",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
            with urlopen(request, timeout=2) as response: result = json.load(response)
            self.assert_terminal_automatic(result)
            self.assertEqual(0, notifier.calls)
        finally:
            server.shutdown(); server.server_close(); thread.join(2); ledger.close()


class DeclarativeAutoApprovalWiringTests(unittest.TestCase):
    """The bundled host path can truly configure auto-approval: one declarative
    --auto-approval policy path wires the checked-in document, the authoritative
    catalogue and the live execution flag into the effective backend."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "catalog.json").write_text(json.dumps(CATALOG))
        (root / "principals.json").write_text(json.dumps({"principals": {
            "agent": {"role": "agent", "enabled": True},
            "control-panel": {"role": "admin", "enabled": True}}}))
        (root / "credentials.json").write_text(json.dumps({"credentials": {}}))
        (root / "auto-approval.json").write_text(json.dumps(DOCUMENT))
        self.root = root

    def tearDown(self):
        self.tmp.cleanup()

    def parse(self, extra=()):
        return build_parser().parse_args([
            "--bind", "127.0.0.1",
            "--catalog", str(self.root / "catalog.json"),
            "--principals", str(self.root / "principals.json"),
            "--credentials", str(self.root / "credentials.json"),
            "--database", str(self.root / "ledger.sqlite3"),
            "--origin", "https://control.example",
            *extra,
        ])

    def compose(self, extra=()):
        return compose(self.parse(extra), master_key=bytes.fromhex("33" * 32),
                       approval_key=bytes.fromhex("22" * 32), admin_password="correct horse battery staple",
                       clock=lambda: 100)

    def test_auto_approval_path_wires_policy_catalogue_and_panel_banner(self):
        app, ledger = self.compose(("--auto-approval", str(self.root / "auto-approval.json")))
        try:
            backend = app.control.backend
            self.assertIsNotNone(backend.auto_approval)
            self.assertEqual("rule-global-simulation", backend.auto_approval.global_simulation_rule["rule_id"])
            self.assertEqual(CATALOG, backend.catalog)
            self.assertIs(False, backend.execution_enabled)
            self.assertIs(False, app.handle("GET", "/health", {}, b"").json()["execution_enabled"])
            login = app.handle("POST", "/login", {}, json.dumps({"username": "control-panel", "password": "correct horse battery staple"}).encode())
            cookie = login.headers["Set-Cookie"].split(";", 1)[0]
            panel = app.handle("GET", "/", {"Cookie": cookie}, b"").body.decode()
            self.assertIn("Automatic except communications and spending", panel)
            self.assertIn("Pause auto-approval", panel)
        finally:
            ledger.close()

    def test_without_the_flag_every_gated_request_asks_a_human(self):
        app, ledger = self.compose()
        try:
            self.assertIsNone(app.control.backend.auto_approval)
            login = app.handle("POST", "/login", {}, json.dumps({"username": "control-panel", "password": "correct horse battery staple"}).encode())
            cookie = login.headers["Set-Cookie"].split(";", 1)[0]
            panel = app.handle("GET", "/", {"Cookie": cookie}, b"").body.decode()
            self.assertIn("No auto-approval policy is configured", panel)
            self.assertNotIn("Automatic except communications and spending", panel)
        finally:
            ledger.close()


if __name__=="__main__": unittest.main()
