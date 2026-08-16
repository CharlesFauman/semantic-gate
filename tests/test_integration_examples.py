#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
EXAMPLES=ROOT/"examples/integrations"
sys.path.insert(0,str(EXAMPLES)); sys.path.insert(0,str(ROOT/"src"))


def load(name: str):
    spec=importlib.util.spec_from_file_location(name,EXAMPLES/(name+".py"))
    if spec is None or spec.loader is None: raise RuntimeError(name)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


class RunnableIntegrationTests(unittest.TestCase):
    def test_downstream_mcp_requires_complete_initialize_and_valid_arguments(self):
        server=load("example_downstream_mcp")
        response,state=server.handle("inventory",{"jsonrpc":"2.0","method":"notifications/initialized","params":{}},server.NEW)
        self.assertIsNone(response); self.assertEqual(server.NEW,state)
        response,state=server.handle("inventory",{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},state)
        self.assertEqual(-32602,response["error"]["code"]); self.assertEqual(server.NEW,state)
        initialize={"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}
        response,state=server.handle("inventory",initialize,state)
        self.assertIn("result",response); self.assertEqual(server.INITIALIZE_RESPONDED,state)
        response,unchanged=server.handle("inventory",initialize,state)
        self.assertEqual(-32600,response["error"]["code"]); self.assertEqual(state,unchanged)
        response,state=server.handle("inventory",{"jsonrpc":"2.0","method":"notifications/initialized","params":{}},state)
        self.assertIsNone(response); self.assertEqual(server.READY,state)
        response,_=server.handle("inventory",{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inventory.available","arguments":{}}},state)
        self.assertEqual(-32602,response["error"]["code"])
        response,_=server.handle("inventory",{"id":4,"method":"tools/list","params":{}},state)
        self.assertEqual(-32600,response["error"]["code"])

    def test_downstream_rejects_unsupported_protocol_and_nonfinite_json(self):
        server=load("example_downstream_mcp")
        message={"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}
        response,state=server.handle("inventory",message,server.NEW)
        self.assertEqual(-32602,response["error"]["code"]); self.assertEqual(server.NEW,state)
        with self.assertRaises(ValueError): server.strict_json_loads(b'{"value":NaN}')

    def test_utf8_byte_limit_rejects_multibyte_payload(self):
        server=load("example_downstream_mcp")
        payload=("é"*((server.MAX_REQUEST_BYTES//2)+1)).encode()+b"\n"
        self.assertGreater(len(payload),server.MAX_REQUEST_BYTES)
        self.assertEqual(-32700,server.parse_line(payload)["error"]["code"])

    def test_stdio_client_times_out_and_terminates_child(self):
        client=load("stdio_mcp_client")
        with tempfile.TemporaryDirectory() as tmp:
            pidfile=Path(tmp)/"pid"
            code="import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); sys.stdin.readline(); time.sleep(30)"
            with self.assertRaises(TimeoutError):
                client.StdioMCPClient([sys.executable,"-c",code,str(pidfile)],timeout_seconds=.1)
            for _ in range(20):
                if pidfile.exists(): break
                time.sleep(.01)
            pid=int(pidfile.read_text())
            with self.assertRaises(ProcessLookupError): os.kill(pid,0)

    def test_stdio_client_rejects_oversized_response(self):
        client=load("stdio_mcp_client")
        code="import sys; sys.stdin.readline(); sys.stdout.write('x'*1048577+'\\n'); sys.stdout.flush()"
        with self.assertRaisesRegex(RuntimeError,"byte limit"):
            client.StdioMCPClient([sys.executable,"-c",code],timeout_seconds=5)

    def test_partial_host_construction_closes_first_client(self):
        adapter=load("existing_mcp_adapter")
        instances=[]
        class FakeClient:
            def __init__(self,*_):
                if instances: raise RuntimeError("second failed")
                self.closed=False; instances.append(self)
            def __enter__(self): return self
            def __exit__(self,*_): self.closed=True
        with mock.patch.object(adapter,"StdioMCPClient",FakeClient), self.assertRaisesRegex(RuntimeError,"second failed"):
            adapter.build_host()
        self.assertTrue(instances[0].closed)

    def test_agent_facing_host_uses_binary_transport(self):
        adapter=load("existing_mcp_adapter")
        class FakeMCP:
            binary=False
            def __init__(self,*_,**__): pass
            def serve_binary(self,incoming,outgoing):
                self.__class__.binary=(incoming is sys.stdin.buffer and outgoing is sys.stdout.buffer)
        class Stack:
            def close(self): pass
        with mock.patch.object(adapter,"build_host",return_value=(object(),None,None,None,Stack())), mock.patch.object(adapter,"SemanticGateMCP",FakeMCP):
            adapter.serve()
        self.assertTrue(FakeMCP.binary)

    def test_real_agent_facing_host_contains_bad_bytes_and_enforces_lifecycle(self):
        def line(message: dict) -> bytes:
            return json.dumps(message,separators=(",",":"),ensure_ascii=False).encode()+b"\n"
        oversized=line({"jsonrpc":"2.0","id":90,"method":"ping","params":{},"padding":"é"*600_000})
        self.assertGreater(len(oversized),1_048_576)
        payload=b"\xff\n"+oversized+b"".join([
            line({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
            line({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),
            line({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}),
            line({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
            line({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}),
        ])
        env=dict(os.environ); env["PYTHONPATH"]=str(ROOT/"src")
        completed=subprocess.run([sys.executable,str(EXAMPLES/"existing_mcp_adapter.py"),"--serve"],input=payload,capture_output=True,timeout=15,env=env)
        self.assertEqual(0,completed.returncode,completed.stderr.decode(errors="replace"))
        responses=[json.loads(item) for item in completed.stdout.splitlines()]
        self.assertEqual([-32700,-32700,-32002],[item["error"]["code"] for item in responses[:3]])
        self.assertIn("serverInfo",responses[3]["result"])
        self.assertEqual(-32002,responses[4]["error"]["code"])
        self.assertIn("tools",responses[5]["result"])

    def test_opt_in_local_mock_proves_enforcing_migration_wiring(self):
        env=dict(os.environ); env["PYTHONPATH"]=str(ROOT/"src")
        completed=subprocess.run([sys.executable,str(EXAMPLES/"existing_mcp_adapter.py"),"--enforcing-demo"],capture_output=True,text=True,check=True,timeout=15,env=env)
        outcome=json.loads(completed.stdout)
        self.assertTrue(outcome["ok"])
        self.assertTrue(outcome["execution_enabled"])
        self.assertTrue(outcome["execution_authority_installed"])
        self.assertTrue(outcome["local_mock_only"])
        self.assertEqual("executed",outcome["state"])
        self.assertEqual(1,outcome["effectful_mcp_calls"])


if __name__=="__main__": unittest.main()
