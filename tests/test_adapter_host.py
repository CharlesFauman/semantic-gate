#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from semantic_gate.adapter_host import AdapterConfigError,DeclarativeAdapterHost,load_adapter_config
from semantic_gate.authorization import AuthorizationBroker,HMACAuthorizationAuthority,SQLiteAuthorizationStore,UnknownOutcomeError
from semantic_gate.engine import ExecutionAuthority
from semantic_gate.engine import ToolRegistry


class FakeClient:
    def __init__(self,command,*,environment,timeout_seconds): self.command=command; self.environment=environment; self.timeout=timeout_seconds; self.calls=[]; self.closed=False
    def call_tool(self,name,args):
        self.calls.append((name,args))
        return {"eligible":True} if name=="inventory.available" else {"order_id":"one"}
    def close(self): self.closed=True


def config(executable: str):
    return {"version":1,"broker_id":"orders-broker","downstreams":{
        "inventory":{"command":[executable,"--inventory"],"pass_environment":["INVENTORY_TOKEN"],"timeout_seconds":5},
        "orders":{"command":[executable,"--orders"],"pass_environment":["ORDERS_TOKEN"],"timeout_seconds":5},
    },"reads":{"inventory.available":{"server":"inventory","tool":"inventory.available"}},
    "actions":{"order.place":{"target":"orders.place","server":"orders","tool":"orders.place","recheck_read":"inventory.available","outcome":"reconcilable"}}}


class DeclarativeAdapterHostTests(unittest.TestCase):
    def test_config_is_closed_absolute_and_has_no_caller_selected_command(self):
        good=load_adapter_config(config("/usr/bin/example-mcp")); self.assertEqual("orders-broker",good["broker_id"])
        cases=[]
        bad=config("relative-command"); cases.append(bad)
        bad=config("/usr/bin/example"); bad["unknown"]=True; cases.append(bad)
        bad=config("/usr/bin/example"); bad["actions"]["order.place"]["server"]="missing"; cases.append(bad)
        bad=config("/usr/bin/example"); bad["downstreams"]["orders"]["pass_environment"]=["BAD=VALUE"]; cases.append(bad)
        bad=config("/usr/bin/example"); bad["actions"]["order.place"]["outcome"]="hopeful"; cases.append(bad)
        for value in cases:
            with self.subTest(value=value),self.assertRaises(AdapterConfigError): load_adapter_config(value)

    def test_host_passes_only_declared_environment_and_uses_fixed_mappings(self):
        clients=[]
        def factory(command,**kwargs): client=FakeClient(command,**kwargs); clients.append(client); return client
        host=DeclarativeAdapterHost(config("/usr/bin/example-mcp"),environment={"INVENTORY_TOKEN":"one","ORDERS_TOKEN":"two","SECRET":"no"},client_factory=factory)
        host.start()
        self.assertEqual({"INVENTORY_TOKEN":"one"},clients[0].environment)
        self.assertEqual({"ORDERS_TOKEN":"two"},clients[1].environment)
        self.assertEqual({"eligible":True},host.call_read("inventory.available",{"sku":"x"}))
        registry=host.register_reads(ToolRegistry())
        self.assertEqual({"eligible":True},registry.call_read("inventory.available",{"sku":"x"}))
        with self.assertRaises(AdapterConfigError): host.call_read("orders.place",{})
        actions=host.broker_actions(); self.assertEqual({"order.place"},set(actions)); self.assertEqual("orders.place",actions["order.place"]["target"])
        self.assertEqual({"eligible":True},actions["order.place"]["recheck"]({"sku":"x"}))
        self.assertEqual({"order_id":"one"},actions["order.place"]["execute"]({"sku":"x"}))
        host.close(); self.assertTrue(all(client.closed for client in clients))

    def test_declarative_host_drives_signed_broker_without_raw_target_selection(self):
        clients=[]
        host=DeclarativeAdapterHost(config("/usr/bin/example-mcp"),environment={"INVENTORY_TOKEN":"one","ORDERS_TOKEN":"two"},client_factory=lambda command,**kwargs: clients.append(FakeClient(command,**kwargs)) or clients[-1]); host.start()
        with tempfile.TemporaryDirectory() as tmp:
            authority=HMACAuthorizationAuthority(b"a"*32,issuer="gate")
            store=SQLiteAuthorizationStore(Path(tmp)/"auth.sqlite3")
            broker=AuthorizationBroker(broker_id="orders-broker",authority=authority,store=store,execution_authority=ExecutionAuthority("host"),revocation_checker=lambda claims:True,expected_policy_hash="a"*64,clock=lambda:100,actions=host.broker_actions())
            token=authority.issue({"authorization_id":"auth_one","issuer":"gate","audience":"orders-broker","request_id":"req","request_hash":"r"*64,"requester":"agent","assurance":"ask","action":"order.place","target":"orders.place","parameters":{"sku":"x"},"parameters_hash":"","policy_hash":"a"*64,"approval_evidence_ids":["approval"],"approval_provenance":{"approval":{"transport":"test"}},"issued_at":100,"expires_at":200,"nonce":"n"*32,"execution_enabled":True,"simulation_only":False})
            store.record_issued(token)
            self.assertEqual("executed",broker.consume_id("auth_one",consumer="agent")["state"])
            self.assertEqual([("orders.place",{"sku":"x"})],clients[1].calls); store.close()
        host.close()

    def test_effectful_transport_failure_is_explicitly_unknown(self):
        class BrokenClient(FakeClient):
            def call_tool(self,tool,args): raise EOFError("response lost after dispatch")
        host=DeclarativeAdapterHost(config("/usr/bin/example"),environment={"INVENTORY_TOKEN":"one","ORDERS_TOKEN":"two"},client_factory=lambda *args,**kwargs:BrokenClient(*args,**kwargs)).start()
        action=host.broker_actions()["order.place"]
        self.assertEqual("reconcilable",action["outcome"])
        with self.assertRaises(UnknownOutcomeError): action["execute"]({"sku":"x"})
        host.close()


if __name__=="__main__": unittest.main()
