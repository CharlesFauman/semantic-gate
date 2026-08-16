#!/usr/bin/env python3
"""Bounded dependency-free stdio MCP client used by the runnable example."""
from __future__ import annotations

import json
import queue
import subprocess
import threading
from collections.abc import Sequence

MAX_RESPONSE_BYTES=1_048_576


def reject_constant(value: str):
    raise ValueError("non-finite JSON number: "+value)


class StdioMCPClient:
    def __init__(self,command: Sequence[str],*,timeout_seconds: float=5):
        self.timeout_seconds=timeout_seconds; self.next_id=1; self.calls=[]; self._closed=False
        self._responses: queue.Queue=queue.Queue()
        self.process=subprocess.Popen(list(command),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,bufsize=0)
        self._reader=threading.Thread(target=self._read_responses,name="example-mcp-reader",daemon=True); self._reader.start()
        try:
            self._request("initialize",{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"semantic-gate-example","version":"1"}})
            self._notify("notifications/initialized",{})
        except Exception:
            self.close(); raise

    def _read_responses(self) -> None:
        assert self.process.stdout is not None
        while True:
            line=self.process.stdout.readline(MAX_RESPONSE_BYTES+1)
            if line==b"": self._responses.put(EOFError("MCP server closed")); return
            if len(line)>MAX_RESPONSE_BYTES or not line.endswith(b"\n"):
                self._responses.put(RuntimeError("MCP response exceeds byte limit")); return
            self._responses.put(line)

    def _send(self,message: dict) -> None:
        if self._closed or self.process.poll() is not None or self.process.stdin is None: raise RuntimeError("MCP server is unavailable")
        encoded=json.dumps(message,separators=(",",":"),allow_nan=False).encode("utf-8")
        if len(encoded)+1>MAX_RESPONSE_BYTES: raise RuntimeError("MCP request exceeds byte limit")
        self.process.stdin.write(encoded+b"\n"); self.process.stdin.flush()

    def _notify(self,method: str,params: dict) -> None:
        self._send({"jsonrpc":"2.0","method":method,"params":params})

    def _request(self,method: str,params: dict) -> dict:
        request_id=self.next_id; self.next_id+=1
        self._send({"jsonrpc":"2.0","id":request_id,"method":method,"params":params})
        try: item=self._responses.get(timeout=self.timeout_seconds)
        except queue.Empty as error: raise TimeoutError("MCP response timed out") from error
        if isinstance(item,Exception): raise item
        try: response=json.loads(item.decode("utf-8"),parse_constant=reject_constant)
        except (UnicodeDecodeError,json.JSONDecodeError,ValueError) as error: raise RuntimeError("invalid MCP JSON response") from error
        if not isinstance(response,dict) or response.get("jsonrpc")!="2.0" or response.get("id")!=request_id: raise RuntimeError("MCP response binding is invalid")
        if "error" in response: raise RuntimeError(str(response["error"].get("message","MCP error")))
        if not isinstance(response.get("result"),dict): raise RuntimeError("MCP result must be an object")
        return response["result"]

    def call_tool(self,name: str,arguments: dict):
        self.calls.append((name,dict(arguments)))
        result=self._request("tools/call",{"name":name,"arguments":arguments})
        if result.get("isError"): raise RuntimeError("downstream MCP tool failed")
        if "structuredContent" not in result: raise RuntimeError("downstream MCP omitted structuredContent")
        return result["structuredContent"]

    def close(self) -> None:
        if self._closed: return
        self._closed=True
        if self.process.stdin:
            try: self.process.stdin.close()
            except OSError: pass
        try: self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try: self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=2)
        self._reader.join(timeout=2)
        if self.process.stdout:
            try: self.process.stdout.close()
            except OSError: pass
        if self.process.returncode not in (0,-15,-9): raise RuntimeError("downstream MCP exited unsuccessfully")

    def __enter__(self): return self
    def __exit__(self,*_): self.close()
