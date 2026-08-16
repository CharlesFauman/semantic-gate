#!/usr/bin/env python3
"""Threaded HTTP runner for the generic Semantic Gate coordinator."""
from __future__ import annotations

import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .auth import CapabilityAuthority
from .authorization import SQLiteAuthorizationStore
from .catalog import build_policy
from .controller import GateControl
from .coordinator import CoreBackend
from .credentials import CredentialRegistry
from .server import SemanticGateApplication
from .storage import Ledger

MAX_BODY = 1_048_576


def make_http_server(app: SemanticGateApplication, bind: str, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "SemanticGate/0.3"

        def _handle(self):
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                self.send_response(413); self.end_headers(); return
            body = self.rfile.read(length) if length else b""
            response = app.handle(self.command, self.path, {key:value for key,value in self.headers.items()}, body)
            self.send_response(response.status)
            for key, value in response.headers.items(): self.send_header(key, value)
            self.send_header("Content-Length", str(len(response.body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            if response.body: self.wfile.write(response.body)

        do_GET = _handle
        do_POST = _handle

        def log_message(self, format, *args):
            return

    return ThreadingHTTPServer((bind, port), Handler)


def _json(path: str | Path):
    return json.loads(Path(path).read_text())


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description="Run the Semantic Gate coordinator")
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--principals", required=True)
    parser.add_argument("--credentials", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--admin-principal", default="control-panel")
    args=parser.parse_args(argv)
    if args.bind in {"0.0.0.0","::"}: parser.error("wildcard binds are forbidden")
    try:
        master=bytes.fromhex(os.environ["SEMANTIC_GATE_MASTER_KEY"])
        approval=bytes.fromhex(os.environ["SEMANTIC_GATE_APPROVAL_KEY"])
        authorization=bytes.fromhex(os.environ["SEMANTIC_GATE_AUTHORIZATION_KEY"])
        password=os.environ["SEMANTIC_GATE_ADMIN_PASSWORD"]
    except (KeyError,ValueError) as error:
        parser.error(f"required secret is missing or invalid: {error}")
    catalog=_json(args.catalog); principals=_json(args.principals)["principals"]
    ledger=Ledger(args.database)
    authorization_store=SQLiteAuthorizationStore(args.database)
    backend=CoreBackend(build_policy(catalog,principals),approval_key=approval,authorization_key=authorization,authorization_store=authorization_store,clock=lambda:int(time.time()))
    app=SemanticGateApplication(GateControl(backend,ledger,clock=lambda:int(time.time()),authorization_store=authorization_store),CapabilityAuthority(master,principals),CredentialRegistry(args.credentials),catalog=catalog,admin_password=password,admin_principal_id=args.admin_principal,origins=[args.origin],clock=lambda:int(time.time()))
    server=make_http_server(app,args.bind,args.port)
    try: server.serve_forever()
    finally: server.server_close(); authorization_store.close(); ledger.close()
    return 0


if __name__=="__main__": raise SystemExit(main())
