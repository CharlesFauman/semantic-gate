#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from semantic_gate.auth import CapabilityAuthority
from semantic_gate.controller import GateControl
from semantic_gate.credentials import CredentialRegistry
from semantic_gate.server import SemanticGateApplication
from semantic_gate.storage import Ledger


class FakeBackend:
    def __init__(self): self.requests={}
    def list_actions(self, principal): return [{"action":"device.power_off"}]
    def explain_action(self, action, principal): return {"action":action,"execution_enabled":False}
    def request_action(self, *, action, parameters, context, trusted_context, requester, idempotency_key):
        request={"request_id":"req_1","request_hash":"h","action":action,"requester":requester,"state":"waiting_for_approval","created_at":100,"parameters":parameters,"context":context,"gates":[]}
        self.requests[request["request_id"]]=request; return dict(request)
    def get_request(self, request_id, requester=None): return dict(self.requests[request_id])
    def cancel_request(self, request_id, requester): self.requests[request_id]["state"]="cancelled"; return dict(self.requests[request_id])
    def approve_request(self, request_id, actor): self.requests[request_id]["state"]="simulated"; return dict(self.requests[request_id])


class SemanticGateApplicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); root=Path(self.tmp.name)
        self.ledger=Ledger(root/"ledger.sqlite3")
        self.control=GateControl(FakeBackend(),self.ledger,clock=lambda:100)
        principals={"agent":{"role":"agent","enabled":True},"control":{"role":"admin","enabled":True}}
        self.authority=CapabilityAuthority(bytes.fromhex("33"*32),principals)
        credentials=root/"credentials.json"; credentials.write_text(json.dumps({"credentials":{"device":{"adapter":"example","kind":"token","value":"never-render-me"}}}))
        self.app=SemanticGateApplication(self.control,self.authority,CredentialRegistry(credentials),catalog={"actions":{"device.power_off":{"risk":"R2","summary":"Power off"}}},admin_password="correct horse battery staple",origins=["https://control.example","http://127.0.0.1:18790"],clock=lambda:100)
        self.agent={"Authorization":f"Bearer {self.authority.token_for('agent')}"}
    def tearDown(self): self.ledger.close(); self.tmp.cleanup()
    def call(self,method,path,headers=None,payload=None): return self.app.handle(method,path,headers or {},b"" if payload is None else json.dumps(payload).encode())

    def test_agent_http_and_mcp_can_propose_but_never_approve(self):
        self.assertEqual(401,self.call("GET","/api/v1/actions").status)
        payload={"action":"device.power_off","parameters":{},"context":{},"idempotency_key":"one"}
        result=self.call("POST","/api/v1/requests",self.agent,payload)
        self.assertEqual(201,result.status); self.assertEqual("agent",result.json()["requester"])
        listed=self.call("POST","/mcp",self.agent,{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}).json()
        names=[tool["name"] for tool in listed["result"]["tools"]]
        self.assertEqual(["list_actions","explain_action","request_action","get_request","cancel_request"],names)
        self.assertEqual(404,self.call("POST","/api/v1/requests/req_1/approve",self.agent,{}).status)

    def test_browser_gets_login_page_and_redirect(self):
        redirect=self.call("GET","/")
        self.assertEqual(303,redirect.status)
        self.assertEqual("/login",redirect.headers["Location"])
        page=self.call("GET","/login")
        self.assertEqual(200,page.status)
        text=page.body.decode()
        self.assertIn("Semantic Gate",text)
        self.assertIn('name=username',text)
        self.assertIn('autocomplete=username',text)
        self.assertIn('value=charles',text)
        self.assertIn('name=password',text)
        self.assertIn('autocomplete=current-password',text)
        self.assertIn('method=post',text)
        self.assertIn('action=/login',text)

    def test_control_panel_login_csrf_approval_and_secret_redaction(self):
        self.assertEqual(403,self.call("POST","/login",payload={"password":"wrong"}).status)
        login=self.call("POST","/login",payload={"password":"correct horse battery staple"})
        self.assertIn("Secure",login.headers["Set-Cookie"])
        cookie=login.headers["Set-Cookie"].split(";",1)[0]; csrf=login.headers["X-CSRF-Token"]
        page=self.call("GET","/",{"Cookie":cookie}); text=page.body.decode()
        self.assertIn("Semantic Gate",text); self.assertIn("device.power_off",text); self.assertNotIn("never-render-me",text)
        self.assertIn("Audit",text); self.assertIn("Pause all",text)
        scripts=re.findall(r"<script>(.*?)</script>",text,flags=re.DOTALL)
        self.assertEqual(1,len(scripts))
        self.assertNotIn("filter(Boolean)}else return",scripts[0])
        self.assertIn("filter(Boolean)}}else return",scripts[0])
        request=self.call("POST","/api/v1/requests",self.agent,{"action":"device.power_off","parameters":{},"context":{},"idempotency_key":"two"}).json()
        self.assertEqual(403,self.call("POST",f"/admin/requests/{request['request_id']}/approve",{"Cookie":cookie},{}).status)
        headers={"Cookie":cookie,"Origin":"https://control.example","X-CSRF-Token":csrf}
        self.assertEqual("simulated",self.call("POST",f"/admin/requests/{request['request_id']}/approve",headers,{}).json()["state"])
        paused=self.call("POST","/admin/controls",headers,{"key":"pause_all","value":True})
        self.assertTrue(paused.json()["pause_all"])
        loopback={"Cookie":cookie,"Origin":"http://127.0.0.1:18790","X-CSRF-Token":csrf}
        resumed=self.call("POST","/admin/controls",loopback,{"key":"pause_all","value":False})
        self.assertFalse(resumed.json()["pause_all"])
        lowercase={"cookie":cookie,"origin":"https://control.example","x-csrf-token":csrf}
        case_insensitive=self.call("POST","/admin/controls",lowercase,{"key":"pause_all","value":True})
        self.assertEqual(200,case_insensitive.status)
        self.assertTrue(case_insensitive.json()["pause_all"])

    def test_control_panel_renders_exact_communication_for_meaningful_approval(self):
        login=self.call("POST","/login",payload={"password":"correct horse battery staple"})
        cookie=login.headers["Set-Cookie"].split(";",1)[0]
        parameters={
            "summary":"Email supplier before purchase",
            "target":"support@example.test",
            "details":{
                "channel":"email",
                "recipient":"support@example.test",
                "subject":"Exact component confirmation",
                "body":"Hello supplier,\nPlease confirm <exact> parts & warranty.",
                "listing_id":"LIST-123",
                "attachments":["requirements.pdf"],
            },
        }
        self.call("POST","/api/v1/requests",self.agent,{"action":"communication.send","parameters":parameters,"context":{},"idempotency_key":"communication-review"})
        text=self.call("GET","/",{"Cookie":cookie}).body.decode()
        self.assertIn("Review exact request",text)
        self.assertIn("support@example.test",text)
        self.assertIn("Exact component confirmation",text)
        self.assertIn("Hello supplier,",text)
        self.assertIn("Please confirm &lt;exact&gt; parts &amp; warranty.",text)
        self.assertNotIn("Please confirm <exact> parts & warranty.",text)
        self.assertIn("LIST-123",text)
        self.assertIn("requirements.pdf",text)
        self.assertNotIn("Canonical request parameters",text)
        self.assertNotIn('&quot;details&quot;',text)

    def test_http_json_rejects_non_finite_values(self):
        response=self.app.handle("POST","/api/v1/requests",self.agent,b'{"action":"device.power_off","parameters":{"x":NaN},"context":{},"idempotency_key":"nan"}')
        self.assertEqual(400,response.status)

    def test_authenticated_audit_observation_is_identity_bound_and_not_an_approval_route(self):
        payload={"event_id":"tool-1:attempted","phase":"attempted","operation":"terminal","semantic_class":"compute.exec.arbitrary","outcome":"started","occurred_at":99,"metadata":{"surface":"hermes"}}
        self.assertEqual(401,self.call("POST","/api/v1/audit-observations",payload=payload).status)
        response=self.call("POST","/api/v1/audit-observations",self.agent,payload)
        self.assertEqual(200,response.status)
        self.assertEqual("agent",response.json()["principal"])
        self.assertEqual("permission_observed",self.ledger.audit_events()[-1]["event"])
        for field,value in (("phase",[]),("outcome",{})):
            malformed={**payload,field:value,"event_id":f"malformed-{field}"}
            with self.subTest(field=field): self.assertEqual(400,self.call("POST","/api/v1/audit-observations",self.agent,malformed).status)
        self.assertEqual(404,self.call("POST","/api/v1/audit-observations/tool-1/approve",self.agent,{}).status)


if __name__=="__main__": unittest.main()
