#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from semantic_gate.authorization import HMACAuthorizationAuthority,SQLiteAuthorizationStore
from semantic_gate.engine import ExecutionAuthority,GatewayEngine,GatePolicyError,ToolRegistry,load_policy

ROOT=Path(__file__).resolve().parents[1]


class Clock:
    def __init__(self,value=100): self.value=value
    def __call__(self): return self.value


class DeliveredNotifier:
    def __init__(self,clock): self.clock=clock
    def notify(self,request,gate):
        return {"notification_id":"notice-"+request["request_id"],"request_id":request["request_id"],"request_hash":request["request_hash"],"notification_gate_id":gate["id"],"recipient":gate["recipient"],"template_hash":hashlib.sha256(gate["template"].encode()).hexdigest(),"delivered_at":self.clock(),"delivered":True}


class TrustedApproval:
    def verify(self,evidence,request): return evidence.get("trusted") is True


def beta_policy(*,simulation=False):
    value=json.loads((ROOT/"examples/calendar-booking/workflow.json").read_text())
    value["version"]=2
    value["authorization"]={"audience":"calendar-broker","ttl_seconds":120}
    value["mode"]="simulation_only" if simulation else "enforcing"
    value["execution_enabled"]=not simulation
    value["workflows"]["calendar.create_event"]["gates"][-1]["simulation_only"]=simulation
    return value


def approval_for(request,*,expires=200):
    gate=next(item for item in request["gates"] if item["kind"]=="approval")
    return {"evidence_id":"approval-one","request_id":request["request_id"],"request_hash":request["request_hash"],"approval_gate_id":gate["id"],"actor":"human","decision":"approve","assurance":"step_up","expires_at":expires,"trusted":True}


class DeferredAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.clock=Clock(); self.calls=[]; self.registry=ToolRegistry()
        self.registry.register_read("calendar.no_conflict",lambda args:{"ok":True})
        self.registry.register_read("provider.terms_current",lambda args:{"current":True})
        self.registry.register_target("calendar.create_event",lambda args:self.calls.append(args) or {"created":True})
        self.authority=HMACAuthorizationAuthority(b"z"*32,issuer="semantic-gate")
        self.store=SQLiteAuthorizationStore(Path(self.tmp.name)/"auth.sqlite3")

    def tearDown(self): self.store.close(); self.tmp.cleanup()

    def engine(self,policy):
        return GatewayEngine(policy,registry=self.registry,notifier=DeliveredNotifier(self.clock),approval_verifier=TrustedApproval(),execution_authority=ExecutionAuthority("legacy-host"),authorization_authority=self.authority,authorization_store=self.store,clock=self.clock)

    def request(self,engine,key="one"):
        return engine.request_action(action="calendar.create_event",parameters={"title":"Example","provider":"Example","start":"2030-01-10T10:00:00Z","end":"2030-01-10T10:30:00Z"},context={},trusted_context={"direct_user_request":True},requester="example-agent",idempotency_key=key)

    def test_version_two_requires_strict_authorization_config_and_authority(self):
        for config in (None,{}, {"audience":"", "ttl_seconds":120},{"audience":"broker","ttl_seconds":0}):
            policy=beta_policy()
            if config is None: policy.pop("authorization")
            else: policy["authorization"]=config
            with self.subTest(config=config),self.assertRaises(GatePolicyError): load_policy(policy)
        proposal_only=GatewayEngine(beta_policy(),registry=self.registry,notifier=DeliveredNotifier(self.clock),approval_verifier=TrustedApproval(),clock=self.clock)
        waiting=self.request(proposal_only,"missing-authority")
        failed=proposal_only.ingest_trusted_approval(waiting["request_id"],approval_for(waiting))
        self.assertEqual("failed",failed["state"]); self.assertNotIn("authorization",failed)

    def test_approval_issues_bounded_authorization_without_calling_target(self):
        engine=self.engine(beta_policy()); waiting=self.request(engine)
        authorized=engine.ingest_trusted_approval(waiting["request_id"],approval_for(waiting))
        self.assertEqual("authorized",authorized["state"]); self.assertEqual([],self.calls)
        self.assertFalse(authorized["execution_possible"]); self.assertTrue(authorized["consumption_possible"])
        metadata=authorized["authorization"]
        self.assertNotIn("signature",metadata)
        token=self.store.get(metadata["authorization_id"])["token"]
        claims=self.authority.verify(token,audience="calendar-broker",now=self.clock())
        self.assertEqual(waiting["request_hash"],claims["request_hash"])
        self.assertEqual("calendar.create_event",claims["action"])
        self.assertEqual("calendar.create_event",claims["target"])
        self.assertTrue(claims["execution_enabled"]); self.assertFalse(claims["simulation_only"])
        self.assertLessEqual(claims["expires_at"],200)
        self.assertEqual("issued",self.store.get(metadata["authorization_id"])["state"])
        with self.assertRaisesRegex(Exception,"not awaiting approval"):
            engine.ingest_trusted_approval(waiting["request_id"],approval_for(waiting))

    def test_authorized_request_cancellation_revokes_unconsumed_token(self):
        engine=self.engine(beta_policy()); waiting=self.request(engine,"cancel")
        authorized=engine.ingest_trusted_approval(waiting["request_id"],approval_for(waiting))
        cancelled=engine.cancel_request(waiting["request_id"],requester="example-agent")
        self.assertEqual("cancelled",cancelled["state"])
        self.assertEqual("cancelled",cancelled["authorization"]["status"])
        self.assertEqual("cancelled",self.store.get(authorized["authorization"]["authorization_id"])["state"])

    def test_simulation_policy_still_defers_and_token_cannot_enable_execution(self):
        engine=self.engine(beta_policy(simulation=True)); waiting=self.request(engine,"sim")
        authorized=engine.ingest_trusted_approval(waiting["request_id"],approval_for(waiting))
        token=self.store.get(authorized["authorization"]["authorization_id"])["token"]
        claims=self.authority.verify(token,audience="calendar-broker",now=self.clock())
        self.assertEqual("authorized",authorized["state"]); self.assertFalse(claims["execution_enabled"]); self.assertTrue(claims["simulation_only"]); self.assertEqual([],self.calls)

    def test_version_one_retains_deprecated_inline_execution_for_compatibility(self):
        legacy=beta_policy(); legacy["version"]=1; legacy.pop("authorization")
        engine=self.engine(legacy); waiting=self.request(engine,"legacy")
        executed=engine.ingest_trusted_approval(waiting["request_id"],approval_for(waiting))
        self.assertEqual("executed",executed["state"]); self.assertEqual(1,len(self.calls))


if __name__=="__main__": unittest.main()
