#!/usr/bin/env python3
"""Bounded line-delimited JSON-RPC stdio MCP server for the runnable example."""
from __future__ import annotations

import argparse
import json
import sys

MAX_REQUEST_BYTES=1_048_576
SUPPORTED_PROTOCOLS={"2025-03-26"}
NEW="new"
INITIALIZE_RESPONDED="initialize_responded"
READY="ready"


def error(request_id,code: int,message: str) -> dict:
    return {"jsonrpc":"2.0","id":request_id,"error":{"code":code,"message":message}}


def reject_constant(value: str):
    raise ValueError("non-finite JSON number: "+value)


def strict_json_loads(raw: bytes):
    return json.loads(raw.decode("utf-8"),parse_constant=reject_constant)


def parse_line(raw: bytes):
    if len(raw)>MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
        return error(None,-32700,"request exceeds byte limit")
    try: return strict_json_loads(raw)
    except (UnicodeDecodeError,json.JSONDecodeError,ValueError): return error(None,-32700,"parse error")


def read_bounded_line(stream):
    raw=stream.readline(MAX_REQUEST_BYTES+1)
    if len(raw)>MAX_REQUEST_BYTES and not raw.endswith(b"\n"):
        while True:
            remainder=stream.readline(MAX_REQUEST_BYTES+1)
            if remainder==b"" or remainder.endswith(b"\n"): break
    return raw


def tool(role: str) -> dict:
    name="inventory.available" if role=="inventory" else "orders.place"
    return {"name":name,"description":"Example downstream tool.","inputSchema":{"type":"object","properties":{"sku":{"type":"string"}},"required":["sku"],"additionalProperties":False}}


def valid_initialize(params: dict) -> bool:
    if set(params)!={"protocolVersion","capabilities","clientInfo"}: return False
    if params["protocolVersion"] not in SUPPORTED_PROTOCOLS or not isinstance(params["capabilities"],dict): return False
    info=params["clientInfo"]
    return isinstance(info,dict) and set(info)=={"name","version"} and all(isinstance(info[key],str) and info[key] for key in ("name","version"))


def handle(role: str,message,state: str) -> tuple[dict | None,str]:
    if state not in {NEW,INITIALIZE_RESPONDED,READY}: raise ValueError("invalid lifecycle state")
    if not isinstance(message,dict) or message.get("jsonrpc")!="2.0" or not isinstance(message.get("method"),str): return error(message.get("id") if isinstance(message,dict) else None,-32600,"invalid request"),state
    has_id="id" in message; request_id=message.get("id")
    if has_id and (type(request_id) not in (int,str) and request_id is not None): return error(None,-32600,"invalid request ID"),state
    method=message["method"]; params=message.get("params",{})
    if not isinstance(params,dict): return (None if not has_id else error(request_id,-32602,"invalid params")),state
    if not has_id:
        if method=="notifications/initialized" and state==INITIALIZE_RESPONDED: return None,READY
        return None,state
    if method=="initialize":
        if state!=NEW: return error(request_id,-32600,"initialize already processed"),state
        if not valid_initialize(params): return error(request_id,-32602,"invalid initialize params"),state
        result={"protocolVersion":params["protocolVersion"],"capabilities":{"tools":{}},"serverInfo":{"name":"example-"+role,"version":"1"}}
        return {"jsonrpc":"2.0","id":request_id,"result":result},INITIALIZE_RESPONDED
    if state!=READY: return error(request_id,-32002,"server not initialized"),state
    if method=="tools/list": result={"tools":[tool(role)]}
    elif method=="tools/call":
        expected=tool(role)["name"]
        if set(params)!={"name","arguments"} or params.get("name")!=expected or not isinstance(params.get("arguments"),dict): return error(request_id,-32602,"invalid tool arguments"),state
        arguments=params["arguments"]
        if set(arguments)!={"sku"} or not isinstance(arguments.get("sku"),str) or not arguments["sku"]: return error(request_id,-32602,"invalid sku"),state
        value={"available":True} if role=="inventory" else {"order_id":"example-order","sku":arguments["sku"]}
        result={"content":[{"type":"text","text":json.dumps(value,sort_keys=True)}],"structuredContent":value,"isError":False}
    else: return error(request_id,-32601,"method not found"),state
    return {"jsonrpc":"2.0","id":request_id,"result":result},state


def main() -> None:
    parser=argparse.ArgumentParser(); parser.add_argument("--role",choices=("inventory","orders"),required=True); args=parser.parse_args(); state=NEW
    incoming=sys.stdin.buffer; outgoing=sys.stdout.buffer
    while True:
        raw=read_bounded_line(incoming)
        if raw==b"": break
        message=parse_line(raw)
        if isinstance(message,dict) and set(message)=={"jsonrpc","id","error"} and message["id"] is None:
            response=message
        else:
            response,state=handle(args.role,message,state)
        if response is not None:
            outgoing.write(json.dumps(response,separators=(",",":"),allow_nan=False).encode()+b"\n"); outgoing.flush()


if __name__=="__main__": main()
