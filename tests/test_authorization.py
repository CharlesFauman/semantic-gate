#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from semantic_gate.authorization import (
    AuthorizationBroker,
    AuthorizationError,
    HMACAuthorizationAuthority,
    SQLiteAuthorizationStore,
)
from semantic_gate.engine import ExecutionAuthority
from semantic_gate.storage import Ledger


class Clock:
    def __init__(self,value=100): self.value=value
    def __call__(self): return self.value


def claims(**changes):
    value={
        "authorization_id":"auth_example","issuer":"gate-host","audience":"orders-broker",
        "request_id":"req_example","request_hash":"r"*64,"requester":"example-agent","assurance":"ask","action":"order.place",
        "target":"orders.place","parameters":{"sku":"example-sku"},"parameters_hash":"",
        "policy_hash":"a"*64,"approval_evidence_ids":["approval_example"],"approval_provenance":{"approval_example":{"transport":"test"}},
        "issued_at":100,"expires_at":200,"nonce":"n"*32,
        "execution_enabled":True,"simulation_only":False,
    }
    value.update(changes)
    return value


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.clock=Clock(); self.authority=HMACAuthorizationAuthority(b"a"*32,issuer="gate-host")
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/"authorization.sqlite3"
    def tearDown(self): self.tmp.cleanup()

    def test_signed_claims_are_exact_bound_expiring_and_tamper_evident(self):
        token=self.authority.issue(claims())
        verified=self.authority.verify(token,audience="orders-broker",now=self.clock())
        self.assertEqual("order.place",verified["action"])
        self.assertEqual(64,len(verified["parameters_hash"]))
        for key,value in (("action","order.other"),("audience","other"),("parameters",{"sku":"other"})):
            tampered=dict(token); tampered[key]=value
            with self.subTest(key=key),self.assertRaises(AuthorizationError): self.authority.verify(tampered,audience="orders-broker",now=self.clock())
        with self.assertRaisesRegex(AuthorizationError,"expired"):
            self.authority.verify(token,audience="orders-broker",now=200)

    def test_store_is_durable_atomic_single_use_and_marks_interrupted_unknown(self):
        token=self.authority.issue(claims())
        store=SQLiteAuthorizationStore(self.path); store.record_issued(token)
        store.begin_consumption("auth_example",consumer="orders-host",now=110)
        with self.assertRaisesRegex(AuthorizationError,"not consumable"):
            store.begin_consumption("auth_example",consumer="other",now=111)
        store.close()
        reopened=SQLiteAuthorizationStore(self.path)
        self.assertEqual("executing",reopened.get("auth_example")["state"])
        reopened.recover_interrupted("auth_example",actor="operator",now=120)
        self.assertEqual("unknown",reopened.get("auth_example")["state"])
        reopened.reconcile("auth_example",outcome="executed",actor="operator",receipt={"order_id":"one"},now=130)
        self.assertEqual("executed",reopened.get("auth_example")["state"])
        reopened.close()

    def test_broker_rechecks_then_executes_exact_fixed_target_once(self):
        calls=[]; checks=[]; store=SQLiteAuthorizationStore(self.path)
        broker=AuthorizationBroker(
            broker_id="orders-broker",authority=self.authority,store=store,
            execution_authority=ExecutionAuthority("orders-host"),revocation_checker=lambda claims:True,expected_policy_hash="a"*64,clock=self.clock,
            actions={"order.place":{"target":"orders.place","outcome":"reconcilable","recheck":lambda args: checks.append(args) or {"eligible":True},"execute":lambda args: calls.append(args) or {"order_id":"one"}}},
        )
        token=self.authority.issue(claims()); store.record_issued(token)
        self.assertFalse(hasattr(broker,"consume"))
        result=broker.consume_id("auth_example",consumer="example-agent")
        self.assertEqual("executed",result["state"]); self.assertEqual(1,len(checks)); self.assertEqual(1,len(calls))
        with self.assertRaises(AuthorizationError): broker.consume_id("auth_example",consumer="example-agent")
        self.assertEqual(1,len(calls)); store.close()

    def test_broker_can_consume_by_non_secret_authorization_id(self):
        calls=[]; store=SQLiteAuthorizationStore(self.path); token=self.authority.issue(claims(authorization_id="auth_by_id")); store.record_issued(token)
        broker=AuthorizationBroker(broker_id="orders-broker",authority=self.authority,store=store,execution_authority=ExecutionAuthority("orders-host"),revocation_checker=lambda claims:True,expected_policy_hash="a"*64,clock=self.clock,actions={"order.place":{"target":"orders.place","outcome":"reconcilable","recheck":lambda args:{"eligible":True},"execute":lambda args:calls.append(args) or {"order_id":"one"}}})
        with self.assertRaisesRegex(AuthorizationError,"different requester"):
            broker.consume_id("auth_by_id",consumer="other-agent")
        self.assertEqual("executed",broker.consume_id("auth_by_id",consumer="example-agent")["state"])
        self.assertEqual(1,len(calls)); store.close()

    def test_revoked_or_unavailable_status_denies_before_target(self):
        calls=[]; store=SQLiteAuthorizationStore(self.path); token=self.authority.issue(claims(authorization_id="auth_revoked")); store.record_issued(token)
        broker=AuthorizationBroker(broker_id="orders-broker",authority=self.authority,store=store,execution_authority=ExecutionAuthority("orders-host"),revocation_checker=lambda claims:False,expected_policy_hash="a"*64,clock=self.clock,actions={"order.place":{"target":"orders.place","outcome":"reconcilable","recheck":lambda args:{"eligible":True},"execute":lambda args:calls.append(args) or {}}})
        with self.assertRaisesRegex(AuthorizationError,"revoked"):
            broker.consume_id("auth_revoked",consumer="example-agent")
        self.assertEqual([],calls); self.assertEqual("issued",store.get("auth_revoked")["state"]); store.close()

    def test_broker_rejects_authorization_from_a_different_policy(self):
        store=SQLiteAuthorizationStore(self.path); store.record_issued(self.authority.issue(claims(authorization_id="auth_stale",policy_hash="b"*64))); calls=[]
        broker=AuthorizationBroker(broker_id="orders-broker",authority=self.authority,store=store,execution_authority=ExecutionAuthority("host"),revocation_checker=lambda claims:True,clock=self.clock,expected_policy_hash="a"*64,actions={"order.place":{"target":"orders.place","outcome":"reconcilable","recheck":lambda args:{"eligible":True},"execute":lambda args:calls.append(args) or {}}})
        with self.assertRaisesRegex(AuthorizationError,"policy"):
            broker.consume_id("auth_stale",consumer="example-agent")
        self.assertEqual([],calls); self.assertEqual("issued",store.get("auth_stale")["state"]); store.close()

    def test_broker_simulates_without_target_and_denied_recheck_fails_closed(self):
        calls=[]; store=SQLiteAuthorizationStore(self.path)
        simulated=AuthorizationBroker(
            broker_id="orders-broker",authority=self.authority,store=store,
            execution_authority=ExecutionAuthority("orders-host"),revocation_checker=lambda claims:True,expected_policy_hash="a"*64,clock=self.clock,
            actions={"order.place":{"target":"orders.place","outcome":"reconcilable","recheck":lambda args:{"eligible":True},"execute":lambda args:calls.append(args) or {}}},
        )
        store.record_issued(self.authority.issue(claims(authorization_id="auth_sim",execution_enabled=False,simulation_only=True)))
        result=simulated.consume_id("auth_sim",consumer="example-agent")
        self.assertEqual("simulated",result["state"]); self.assertEqual([],calls)
        denied=AuthorizationBroker(
            broker_id="orders-broker",authority=self.authority,store=store,
            execution_authority=ExecutionAuthority("orders-host"),revocation_checker=lambda claims:True,expected_policy_hash="a"*64,clock=self.clock,
            actions={"order.place":{"target":"orders.place","outcome":"reconcilable","recheck":lambda args:{"eligible":False},"execute":lambda args:calls.append(args) or {}}},
        )
        store.record_issued(self.authority.issue(claims(authorization_id="auth_deny")))
        with self.assertRaisesRegex(AuthorizationError,"recheck"):
            denied.consume_id("auth_deny",consumer="example-agent")
        self.assertEqual("failed",store.get("auth_deny")["state"]); self.assertEqual([],calls); store.close()

    def test_timeout_becomes_unknown_and_requires_reconciliation_not_retry(self):
        store=SQLiteAuthorizationStore(self.path)
        broker=AuthorizationBroker(broker_id="orders-broker",authority=self.authority,store=store,execution_authority=ExecutionAuthority("orders-host"),revocation_checker=lambda claims:True,expected_policy_hash="a"*64,clock=self.clock,actions={"order.place":{"target":"orders.place","outcome":"reconcilable","recheck":lambda args:{"eligible":True},"execute":lambda args:(_ for _ in ()).throw(TimeoutError("lost response"))}})
        token=self.authority.issue(claims(authorization_id="auth_unknown")); store.record_issued(token)
        with self.assertRaisesRegex(AuthorizationError,"unknown"):
            broker.consume_id("auth_unknown",consumer="example-agent")
        self.assertEqual("unknown",store.get("auth_unknown")["state"])
        with self.assertRaises(AuthorizationError): broker.consume_id("auth_unknown",consumer="example-agent")
        store.reconcile("auth_unknown",outcome="executed",actor="operator",receipt={"order_id":"recovered"},now=120)
        self.assertEqual("executed",store.get("auth_unknown")["state"]); store.close()

    def test_two_store_connections_reserve_one_attempt(self):
        first=SQLiteAuthorizationStore(self.path); second=SQLiteAuthorizationStore(self.path)
        token=self.authority.issue(claims(authorization_id="auth_race")); first.record_issued(token)
        calls=[]; lock=threading.Lock(); barrier=threading.Barrier(2); outcomes=[]
        def execute(args):
            with lock: calls.append(args)
            return {"order_id":"one"}
        def run(store):
            broker=AuthorizationBroker(broker_id="orders-broker",authority=self.authority,store=store,execution_authority=ExecutionAuthority("host"),revocation_checker=lambda claims:True,expected_policy_hash="a"*64,clock=self.clock,actions={"order.place":{"target":"orders.place","outcome":"reconcilable","recheck":lambda args:{"eligible":True},"execute":execute}})
            barrier.wait()
            try: outcomes.append(broker.consume_id("auth_race",consumer="example-agent")["state"])
            except AuthorizationError: outcomes.append("rejected")
        threads=[threading.Thread(target=run,args=(first,)),threading.Thread(target=run,args=(second,))]
        [item.start() for item in threads]; [item.join() for item in threads]
        self.assertEqual(["executed","rejected"],sorted(outcomes)); self.assertEqual(1,len(calls))
        first.close(); second.close()

    def test_rechecks_expiry_and_revocation_immediately_before_dispatch(self):
        store=SQLiteAuthorizationStore(self.path); calls=[]; checks=[]
        token=self.authority.issue(claims(authorization_id="auth_toc",expires_at=102)); store.record_issued(token)
        def recheck(args): checks.append(args); self.clock.value=102; return {"eligible":True}
        broker=AuthorizationBroker(broker_id="orders-broker",authority=self.authority,store=store,execution_authority=ExecutionAuthority("host"),revocation_checker=lambda claims:True,expected_policy_hash="a"*64,clock=self.clock,actions={"order.place":{"target":"orders.place","outcome":"reconcilable","recheck":recheck,"execute":lambda args:calls.append(args) or {}}})
        with self.assertRaisesRegex(AuthorizationError,"expired"):
            broker.consume_id("auth_toc",consumer="example-agent")
        self.assertEqual([],calls); self.assertEqual("failed",store.get("auth_toc")["state"]); store.close()

    def test_every_post_dispatch_exception_is_unknown_and_non_retryable(self):
        for index,error in enumerate((EOFError("closed"),ConnectionError("lost"),RuntimeError("malformed"),AuthorizationError("bad result"))):
            with self.subTest(error=type(error).__name__):
                path=Path(self.tmp.name)/f"unknown-{index}.sqlite3"; store=SQLiteAuthorizationStore(path); authorization_id=f"auth_post_{index}"
                store.record_issued(self.authority.issue(claims(authorization_id=authorization_id)))
                broker=AuthorizationBroker(broker_id="orders-broker",authority=self.authority,store=store,execution_authority=ExecutionAuthority("host"),revocation_checker=lambda claims:True,expected_policy_hash="a"*64,clock=self.clock,actions={"order.place":{"target":"orders.place","outcome":"reconcilable","recheck":lambda args:{"eligible":True},"execute":lambda args,error=error:(_ for _ in ()).throw(error)}})
                with self.assertRaisesRegex(AuthorizationError,"unknown"):
                    broker.consume_id(authorization_id,consumer="example-agent")
                self.assertEqual("unknown",store.get(authorization_id)["state"]); store.close()

    def test_receipt_persistence_failure_after_target_is_never_failed(self):
        class CompletionFailStore(SQLiteAuthorizationStore):
            def complete(self,*args,**kwargs): raise OSError("disk unavailable after target returned")
        store=CompletionFailStore(self.path); store.record_issued(self.authority.issue(claims(authorization_id="auth_receipt"))); calls=[]
        broker=AuthorizationBroker(broker_id="orders-broker",authority=self.authority,store=store,execution_authority=ExecutionAuthority("host"),revocation_checker=lambda claims:True,expected_policy_hash="a"*64,clock=self.clock,actions={"order.place":{"target":"orders.place","outcome":"reconcilable","recheck":lambda args:{"eligible":True},"execute":lambda args:calls.append(args) or {"order_id":"one"}}})
        with self.assertRaisesRegex(AuthorizationError,"unknown"):
            broker.consume_id("auth_receipt",consumer="example-agent")
        self.assertEqual(1,len(calls)); self.assertEqual("unknown",store.get("auth_receipt")["state"]); store.close()

    def test_authorization_transitions_atomically_project_request_state(self):
        ledger=Ledger(self.path); request={"request_id":"req_example","request_hash":"r"*64,"action":"order.place","requester":"example-agent","state":"authorized","created_at":100,"updated_at":100,"parameters":{},"context":{},"gates":[],"consumption_possible":True,"authorization":{"authorization_id":"auth_projection","status":"issued"}}
        ledger.record_request(request,event="authorized",actor="human")
        store=SQLiteAuthorizationStore(self.path); store.record_issued(self.authority.issue(claims(authorization_id="auth_projection")))
        store.begin_consumption("auth_projection",consumer="example-agent",now=110)
        self.assertEqual("consuming",ledger.get_request("req_example")["state"])
        store.record_issued(self.authority.issue(claims(authorization_id="auth_projection")))
        self.assertEqual("consuming",ledger.get_request("req_example")["state"])
        self.assertEqual(110,ledger.get_request("req_example")["updated_at"])
        store.mark_unknown("auth_projection",receipt={"error_type":"EOFError"},now=111)
        projected=ledger.get_request("req_example"); self.assertEqual("outcome_unknown",projected["state"]); self.assertFalse(projected["consumption_possible"])
        store.reconcile("auth_projection",outcome="executed",actor="operator",receipt={"order_id":"one"},now=112)
        self.assertEqual("executed",ledger.get_request("req_example")["state"])
        store.close(); ledger.close()

    def test_cancel_is_idempotent_for_snapshot_repair(self):
        store=SQLiteAuthorizationStore(self.path); store.record_issued(self.authority.issue(claims(authorization_id="auth_cancel")))
        self.assertEqual("cancelled",store.cancel("auth_cancel",now=110)["state"])
        self.assertEqual("cancelled",store.cancel("auth_cancel",now=111)["state"]); store.close()

    def test_bulk_revoke_reserves_writer_before_selecting_issued_rows(self):
        store=SQLiteAuthorizationStore(self.path); store.record_issued(self.authority.issue(claims(authorization_id="auth_bulk"))); statements=[]
        store.db.set_trace_callback(lambda statement:statements.append(statement.upper()))
        self.assertEqual(1,store.revoke_all_issued(actor="operator",now=110))
        begin=next(index for index,statement in enumerate(statements) if statement.startswith("BEGIN IMMEDIATE"))
        select=next(index for index,statement in enumerate(statements) if "SELECT AUTHORIZATION_ID,REQUEST_ID FROM AUTHORIZATIONS WHERE STATE='ISSUED'" in statement)
        self.assertLess(begin,select); self.assertEqual("cancelled",store.get("auth_bulk")["state"]); store.close()


if __name__=="__main__": unittest.main()
