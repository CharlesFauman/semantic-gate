#!/usr/bin/env python3
"""Wrap real stdio MCP subprocesses behind a Semantic Gate MCP host."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import sys
from pathlib import Path

from semantic_gate import ExecutionAuthority,GatewayEngine,ToolRegistry,load_policy
from semantic_gate.coordinator import HostApprovalVerifier
from semantic_gate.engine import GatePolicyError
from semantic_gate.mcp import SemanticGateMCP
from stdio_mcp_client import StdioMCPClient


class DeliveredNotifier:
    def notify(self,request: dict,gate: dict) -> dict:
        return {"notification_id":"notice-"+request["request_id"],"request_id":request["request_id"],"request_hash":request["request_hash"],"notification_gate_id":gate["id"],"recipient":gate["recipient"],"template_hash":hashlib.sha256(gate["template"].encode()).hexdigest(),"delivered_at":100,"delivered":True}


def policy(*,enforcing: bool=False) -> dict:
    document={"version":1,"mode":"simulation_only","execution_enabled":False,"workflows":{"order.place":{
        "description":"Place an allowlisted order.","principals":["example-agent"],"target_tool":"orders.place",
        "parameter_schema":{"type":"object","additionalProperties":False,"required":["sku"],"properties":{"sku":{"type":"string","enum":["example-sku"]}}},
        "gates":[
            {"id":"schema","kind":"schema","requires":[]},
            {"id":"stock","kind":"tool","requires":["schema"],"tool":"inventory.available","input":{"sku":"$parameters.sku"},"expect":{"path":"available","op":"eq","value":True},"recheck":False},
            {"id":"notify","kind":"notify","requires":["stock"],"recipient":"human_owner","template":"Review order"},
            {"id":"approval","kind":"approval","requires":["notify"],"level":"human_approve_once","ttl_seconds":300},
            {"id":"stock_again","kind":"tool","requires":["approval"],"tool":"inventory.available","input":{"sku":"$parameters.sku"},"expect":{"path":"available","op":"eq","value":True},"recheck":True},
            {"id":"execute","kind":"execute","requires":["stock_again"],"tool":"orders.place","simulation_only":True},
        ],
    }}}
    if enforcing:
        document["mode"]="enforcing"; document["execution_enabled"]=True
        document["workflows"]["order.place"]["gates"][-1]["simulation_only"]=False
    return document


def build_host(*,enforcing: bool=False):
    server=Path(__file__).with_name("example_downstream_mcp.py")
    stack=ExitStack()
    try:
        inventory=stack.enter_context(StdioMCPClient([sys.executable,str(server),"--role","inventory"]))
        orders=stack.enter_context(StdioMCPClient([sys.executable,str(server),"--role","orders"]))
        registry=ToolRegistry(); verifier=HostApprovalVerifier(b"example-approval-key-material-32b")
        # Only this trusted host sees the downstream clients. The agent-facing
        # MCP contains proposal/status/cancel methods, never orders.place.
        registry.register_read("inventory.available",lambda args:inventory.call_tool("inventory.available",args))
        registry.register_target("orders.place",lambda args:orders.call_tool("orders.place",args))
        authority=ExecutionAuthority("local-mock-demo-host") if enforcing else None
        engine=GatewayEngine(load_policy(policy(enforcing=enforcing)),registry=registry,notifier=DeliveredNotifier(),approval_verifier=verifier,execution_authority=authority,clock=lambda:100)
        return engine,verifier,inventory,orders,stack
    except Exception:
        stack.close(); raise


def run_demo(*,enforcing: bool=False) -> None:
    engine,verifier,inventory,orders,stack=build_host(enforcing=enforcing)
    try:
        surface=SemanticGateMCP(engine,principal="example-agent",trusted_context={"surface":"example-host"})
        try: surface.call_tool("orders.place",{"sku":"example-sku"})
        except GatePolicyError: direct_target_denied=True
        else: direct_target_denied=False
        request=engine.request_action(action="order.place",parameters={"sku":"example-sku"},context={},trusted_context={},requester="example-agent",idempotency_key="mcp-enforcing-1" if enforcing else "mcp-adapter-1")
        approval=next(g for g in request["gates"] if g["kind"]=="approval")
        evidence={"evidence_id":"approval-example","request_id":request["request_id"],"request_hash":request["request_hash"],"approval_gate_id":approval["id"],"actor":"example-human","decision":"approve","assurance":"ask","expires_at":200}
        evidence["signature"]=verifier.sign(evidence)
        result=engine.ingest_trusted_approval(request["request_id"],evidence)
        expected="executed" if enforcing else "simulated"
        assert result["state"]==expected and len(inventory.calls)==2 and len(orders.calls)==(1 if enforcing else 0) and direct_target_denied
        output={"ok":True,"execution_enabled":enforcing,"execution_authority_installed":enforcing,"local_mock_only":enforcing,"direct_agent_target_denied":direct_target_denied,"real_stdio_jsonrpc":True,"agent_facing_mcp_host":True,"downstream_processes":2,"state":result["state"],"read_mcp_calls":len(inventory.calls),"effectful_mcp_calls":len(orders.calls)}
        if not enforcing: output["would_call"]=result["would_call"]["tool"]
        print(json.dumps(output,sort_keys=True))
    finally:
        stack.close()


def serve() -> None:
    engine,_,_,_,stack=build_host()
    try:
        SemanticGateMCP(engine,principal="example-agent",trusted_context={"surface":"example-host"}).serve_binary(sys.stdin.buffer,sys.stdout.buffer)
    finally:
        stack.close()


def main() -> None:
    parser=argparse.ArgumentParser(); group=parser.add_mutually_exclusive_group(); group.add_argument("--serve",action="store_true",help="serve the simulation-only agent-facing MCP over stdio"); group.add_argument("--enforcing-demo",action="store_true",help="execute only the bundled local mock target with explicit host authority"); args=parser.parse_args()
    if args.serve: serve()
    else: run_demo(enforcing=args.enforcing_demo)


if __name__=="__main__": main()
