#!/usr/bin/env python3
"""Wrap real stdio MCP subprocesses behind deferred Semantic Gate authorization."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from semantic_gate import ExecutionAuthority,GatewayEngine,ToolRegistry,load_policy
from semantic_gate.authorization import AuthorizationBroker,HMACAuthorizationAuthority,SQLiteAuthorizationStore
from semantic_gate.coordinator import HostApprovalVerifier
from semantic_gate.engine import GatePolicyError
from semantic_gate.mcp import SemanticGateMCP
from stdio_mcp_client import StdioMCPClient


class DeliveredNotifier:
    def notify(self,request: dict,gate: dict) -> dict:
        return {"notification_id":"notice-"+request["request_id"],"request_id":request["request_id"],"request_hash":request["request_hash"],"notification_gate_id":gate["id"],"recipient":gate["recipient"],"template_hash":hashlib.sha256(gate["template"].encode()).hexdigest(),"delivered_at":100,"delivered":True}


def policy(*,enforcing: bool=False) -> dict:
    document={"version":2,"mode":"simulation_only","execution_enabled":False,"authorization":{"audience":"orders-broker","ttl_seconds":300},"workflows":{"order.place":{
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
    server=Path(__file__).with_name("example_downstream_mcp.py"); stack=ExitStack()
    try:
        inventory=stack.enter_context(StdioMCPClient([sys.executable,str(server),"--role","inventory"]))
        orders=stack.enter_context(StdioMCPClient([sys.executable,str(server),"--role","orders"]))
        temp=stack.enter_context(tempfile.TemporaryDirectory()); store=SQLiteAuthorizationStore(Path(temp)/"authorization.sqlite3"); stack.callback(store.close)
        authority=HMACAuthorizationAuthority(b"example-authorization-key-material",issuer="example-gate-host")
        registry=ToolRegistry(); verifier=HostApprovalVerifier(b"example-approval-key-material-32b")
        # The engine sees only reads. The effectful orders client exists only in the broker.
        registry.register_read("inventory.available",lambda args:inventory.call_tool("inventory.available",args))
        loaded_policy=load_policy(policy(enforcing=enforcing))
        engine=GatewayEngine(loaded_policy,registry=registry,notifier=DeliveredNotifier(),approval_verifier=verifier,authorization_authority=authority,authorization_store=store,clock=lambda:100)
        broker=AuthorizationBroker(broker_id="orders-broker",authority=authority,store=store,execution_authority=ExecutionAuthority("local-mock-demo-host"),revocation_checker=lambda claims:store.get(claims["authorization_id"])["state"] in {"issued","executing"},expected_policy_hash=engine.policy_hash,clock=lambda:100,actions={"order.place":{"target":"orders.place","outcome":"reconcilable","recheck":lambda args:{"eligible":inventory.call_tool("inventory.available",args)["available"] is True},"execute":lambda args:orders.call_tool("orders.place",args)}})
        return engine,verifier,broker,inventory,orders,stack
    except Exception:
        stack.close(); raise


def run_demo(*,enforcing: bool=False) -> None:
    engine,verifier,broker,inventory,orders,stack=build_host(enforcing=enforcing)
    try:
        surface=SemanticGateMCP(engine,principal="example-agent",trusted_context={"surface":"example-host"})
        try: surface.call_tool("orders.place",{"sku":"example-sku"})
        except GatePolicyError: direct_target_denied=True
        else: direct_target_denied=False
        request=engine.request_action(action="order.place",parameters={"sku":"example-sku"},context={},trusted_context={},requester="example-agent",idempotency_key="mcp-enforcing-1" if enforcing else "mcp-adapter-1")
        approval=next(g for g in request["gates"] if g["kind"]=="approval")
        evidence={"evidence_id":"approval-example","request_id":request["request_id"],"request_hash":request["request_hash"],"approval_gate_id":approval["id"],"actor":"example-human","decision":"approve","assurance":"ask","expires_at":200}
        evidence["signature"]=verifier.sign(evidence)
        authorized=engine.ingest_trusted_approval(request["request_id"],evidence)
        assert authorized["state"]=="authorized" and not orders.calls and direct_target_denied
        # The agent independently decides to consume now; approval did not execute.
        consumed=broker.consume_id(authorized["authorization"]["authorization_id"],consumer="example-agent")
        expected="executed" if enforcing else "simulated"
        assert consumed["state"]==expected and len(inventory.calls)==3 and len(orders.calls)==(1 if enforcing else 0)
        output={"ok":True,"execution_enabled":enforcing,"execution_authority_installed":True,"local_mock_only":enforcing,"direct_agent_target_denied":direct_target_denied,"authorization_issued":True,"authorization_consumed":True,"approval_state":authorized["state"],"real_stdio_jsonrpc":True,"agent_facing_mcp_host":True,"downstream_processes":2,"state":consumed["state"],"read_mcp_calls":len(inventory.calls),"effectful_mcp_calls":len(orders.calls)}
        print(json.dumps(output,sort_keys=True))
    finally: stack.close()


def serve() -> None:
    engine,_,_,_,_,stack=build_host()
    try: SemanticGateMCP(engine,principal="example-agent",trusted_context={"surface":"example-host"}).serve_binary(sys.stdin.buffer,sys.stdout.buffer)
    finally: stack.close()


def main() -> None:
    parser=argparse.ArgumentParser(); group=parser.add_mutually_exclusive_group(); group.add_argument("--serve",action="store_true",help="serve the simulation-only agent-facing MCP over stdio"); group.add_argument("--enforcing-demo",action="store_true",help="consume authorization only against the bundled local mock target"); args=parser.parse_args()
    if args.serve: serve()
    else: run_demo(enforcing=args.enforcing_demo)


if __name__=="__main__": main()
