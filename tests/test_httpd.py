#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import urlopen

from semantic_gate.httpd import build_parser, compose, make_http_server
from tests.test_server import SemanticGateApplicationTests

CATALOG = {"version": 1, "actions": {
    "code.edit_file": {"domain": "code", "risk": "R1", "effect": "write", "summary": "Apply one reviewed patch", "approval": "separate_confirmation", "gate_class": "automatic"},
    "communication.send": {"domain": "communication", "risk": "R2", "effect": "external_write", "summary": "Send a message to a person", "approval": "separate_confirmation", "gate_class": "human_communication"},
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
