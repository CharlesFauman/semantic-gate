#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import tempfile
import unittest
from urllib.parse import urlencode
from pathlib import Path

from semantic_gate.auth import CapabilityAuthority
from semantic_gate.autoapproval import PROHIBITED_CLASSES, AutoApprovalPolicy
from semantic_gate.controller import GateControl
from semantic_gate.credentials import CredentialRegistry
from semantic_gate.server import PANEL_COLORS, PANEL_CONTRAST_PAIRS, SemanticGateApplication
from semantic_gate.storage import Ledger


class FakeBackend:
    def __init__(self): self.requests={}; self.auto_decision=None
    def list_actions(self, principal): return [{"action":"device.power_off"}]
    def explain_action(self, action, principal): return {"action":action,"execution_enabled":False}
    def request_action(self, *, action, parameters, context, trusted_context, requester, idempotency_key, minimum_control="policy"):
        request={"request_id":"req_"+re.sub(r"[^a-z0-9]","",idempotency_key),"request_hash":"h"*64,"action":action,"requester":requester,"state":"waiting_for_approval","created_at":100,"parameters":parameters,"context":context,"minimum_control":minimum_control,"policy_control":"ask","effective_control":"step_up" if minimum_control=="step_up" else "ask","gates":[{"id":"approval","kind":"approval","status":"waiting","evidence":{"ttl_seconds":300}}]}
        request["approval_challenge"]={"request_id":request["request_id"],"request_hash":request["request_hash"],"approval_gate_id":"approval","expires_at":400}
        self.requests[request["request_id"]]=request; return dict(request)
    def approval_challenge(self, request_id): return dict(self.requests[request_id]["approval_challenge"])
    def get_request(self, request_id, requester=None): return dict(self.requests[request_id])
    def cancel_request(self, request_id, requester): self.requests[request_id]["state"]="cancelled"; return dict(self.requests[request_id])
    def approve_request(self, request_id, actor, challenge): self.requests[request_id]["state"]="simulated"; return dict(self.requests[request_id])
    def deny_request(self, request_id, actor, challenge): self.requests[request_id]["state"]="denied"; return dict(self.requests[request_id])
    def auto_approval_decision(self, request, *, paused=False, disabled_rules=()): return None if self.auto_decision is None else dict(self.auto_decision)
    def auto_approve(self, request_id, decision):
        self.requests[request_id]["state"]="simulated"
        audit={"auto_approved":True,"rule_id":decision["rule_id"],"rule_version":1,"policy_version":7,"request_id":request_id,"request_hash":"h"*64,"commit":None,"action_class":"global_simulation","reason_code":decision["reason_code"],"authorizes_execution":False}
        return dict(self.requests[request_id]),{"evidence_id":"auto_1"},audit


class SemanticGateApplicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); root=Path(self.tmp.name)
        self.ledger=Ledger(root/"ledger.sqlite3")
        self.control=GateControl(FakeBackend(),self.ledger,clock=lambda:100)
        principals={"agent":{"role":"agent","enabled":True},"observer":{"role":"observer","enabled":True},"control":{"role":"admin","enabled":True}}
        self.authority=CapabilityAuthority(bytes.fromhex("33"*32),principals)
        credentials=root/"credentials.json"; credentials.write_text(json.dumps({"credentials":{"device":{"adapter":"example","kind":"token","value":"never-render-me"}}}))
        self.app=SemanticGateApplication(self.control,self.authority,CredentialRegistry(credentials),catalog={"actions":{"device.power_off":{"risk":"R2","effect":"write","summary":"Power off an allowlisted display","presentation":{"proposed_effect":"Power off the allowlisted meeting-room display","reason":"Display is idle outside booked hours","node":"node-example-1","safe_target_field":"target","safe_target_values":["example-display"],"spends":False,"communicates":False,"changes_state":True}}}},admin_password="correct horse battery staple",origins=["https://control.example","http://127.0.0.1:18790"],clock=lambda:100)
        self.agent={"Authorization":f"Bearer {self.authority.token_for('agent')}"}
        self.observer={"Authorization":f"Bearer {self.authority.token_for('observer')}"}
    def tearDown(self): self.ledger.close(); self.tmp.cleanup()
    def call(self,method,path,headers=None,payload=None): return self.app.handle(method,path,headers or {},b"" if payload is None else json.dumps(payload).encode())
    def form(self,method,path,headers=None,fields=None):
        return self.app.handle(method,path,{"Content-Type":"application/x-www-form-urlencoded",**(headers or {})},urlencode(fields or {}).encode())

    def test_agent_http_and_mcp_can_propose_but_never_approve(self):
        self.assertEqual(401,self.call("GET","/api/v1/actions").status)
        payload={"action":"device.power_off","parameters":{},"context":{},"idempotency_key":"one"}
        result=self.call("POST","/api/v1/requests",self.agent,payload)
        self.assertEqual(201,result.status); self.assertEqual("agent",result.json()["requester"])
        listed=self.call("POST","/mcp",self.agent,{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}).json()
        names=[tool["name"] for tool in listed["result"]["tools"]]
        self.assertEqual(["list_actions","explain_action","request_action","get_request","cancel_request"],names)
        self.assertEqual(404,self.call("POST","/api/v1/requests/req_1/approve",self.agent,{}).status)

    def test_observer_can_only_submit_audit_observations(self):
        payload={"event_id":"device-1:attempted","phase":"attempted","operation":"desktop.application.open","semantic_class":"desktop.control.launch","outcome":"started","occurred_at":99,"metadata":{"surface":"device-actions"}}
        response=self.call("POST","/api/v1/audit-observations",self.observer,payload)
        self.assertEqual(200,response.status); self.assertEqual("observer",response.json()["principal"])
        request={"action":"device.power_off","parameters":{},"context":{},"idempotency_key":"observer-nope"}
        self.assertEqual(403,self.call("GET","/api/v1/actions",self.observer).status)
        self.assertEqual(403,self.call("POST","/api/v1/requests",self.observer,request).status)
        self.assertEqual(403,self.call("GET","/api/v1/requests",self.observer).status)
        self.assertEqual(403,self.call("POST","/mcp",self.observer,{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}).status)

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
        self.assertNotIn('value='+'char'+'les',text)
        self.assertIn('name=password',text)
        self.assertIn('autocomplete=current-password',text)
        self.assertIn('method=post',text)
        self.assertIn('action=/login',text)
        self.assertNotIn('<script>',text)

    def test_no_javascript_login_and_exact_decision_forms(self):
        login=self.form("POST","/login",fields={"username":"control","password":"correct horse battery staple"})
        self.assertEqual(303,login.status)
        self.assertEqual("/",login.headers["Location"])
        cookie=login.headers["Set-Cookie"].split(";",1)[0]
        request=self.call("POST","/api/v1/requests",self.agent,{"action":"device.power_off","parameters":{},"context":{},"idempotency_key":"no-js"}).json()
        panel=self.call("GET","/",{"Cookie":cookie}).body.decode()
        self.assertIn("<meta http-equiv=refresh content=20>",panel)
        self.assertIn(f"action='/admin/requests/{request['request_id']}/approve'",panel)
        self.assertIn(f"action='/admin/requests/{request['request_id']}/deny'",panel)
        self.assertNotIn("data-op='approve'",panel)
        self.assertNotIn("data-op='deny'",panel)
        csrf=re.search(r"name='csrf_token' value='([^']+)'",panel).group(1)
        fields={"csrf_token":csrf,**{key:str(value) for key,value in request["approval_challenge"].items()}}
        rejected=self.form("POST",f"/admin/requests/{request['request_id']}/approve",{"Cookie":cookie},fields)
        self.assertEqual(403,rejected.status)
        tampered={**fields,"request_hash":"bad"}
        conflict=self.form("POST",f"/admin/requests/{request['request_id']}/approve",{"Cookie":cookie,"Origin":"https://control.example"},tampered)
        self.assertEqual(409,conflict.status)
        approved=self.form("POST",f"/admin/requests/{request['request_id']}/approve",{"Cookie":cookie,"Origin":"https://control.example"},fields)
        self.assertEqual(303,approved.status)
        self.assertEqual("/",approved.headers["Location"])
        self.assertEqual("simulated",self.control.backend.requests[request["request_id"]]["state"])

    def test_login_and_decision_form_fields_remain_separate(self):
        bad_login=self.form("POST","/login",fields={"username":"control","password":"correct horse battery staple","request_id":"req_1"})
        self.assertEqual(403,bad_login.status)
        login=self.form("POST","/login",fields={"username":"control","password":"correct horse battery staple"})
        cookie=login.headers["Set-Cookie"].split(";",1)[0]
        request=self.call("POST","/api/v1/requests",self.agent,{"action":"device.power_off","parameters":{},"context":{},"idempotency_key":"separate"}).json()
        panel=self.call("GET","/",{"Cookie":cookie}).body.decode()
        csrf=re.search(r"name='csrf_token' value='([^']+)'",panel).group(1)
        fields={"csrf_token":csrf,"username":"control","password":"correct horse battery staple",**{key:str(value) for key,value in request["approval_challenge"].items()}}
        response=self.form("POST",f"/admin/requests/{request['request_id']}/approve",{"Cookie":cookie,"Origin":"https://control.example"},fields)
        self.assertEqual(400,response.status)

    def test_control_panel_login_csrf_approval_and_secret_redaction(self):
        self.assertEqual(403,self.call("POST","/login",payload={"username":"control","password":"wrong"}).status)
        self.assertEqual(403,self.call("POST","/login",payload={"password":"correct horse battery staple"}).status)
        self.assertEqual(403,self.call("POST","/login",payload={"username":"agent","password":"correct horse battery staple"}).status)
        login=self.call("POST","/login",payload={"username":"control","password":"correct horse battery staple"})
        self.assertIn("Secure",login.headers["Set-Cookie"])
        cookie=login.headers["Set-Cookie"].split(";",1)[0]; csrf=login.headers["X-CSRF-Token"]
        page=self.call("GET","/",{"Cookie":cookie}); text=page.body.decode()
        self.assertIn("Semantic Gate",text); self.assertIn("device.power_off",text); self.assertNotIn("never-render-me",text)
        self.assertIn("Audit",text); self.assertIn("Pause all",text)
        self.assertEqual([],re.findall(r"<script",text))
        request=self.call("POST","/api/v1/requests",self.agent,{"action":"device.power_off","parameters":{},"context":{},"idempotency_key":"two"}).json()
        self.assertEqual(403,self.call("POST",f"/admin/requests/{request['request_id']}/approve",{"Cookie":cookie},{}).status)
        headers={"Cookie":cookie,"Origin":"https://control.example","X-CSRF-Token":csrf}
        self.assertEqual(409,self.call("POST",f"/admin/requests/{request['request_id']}/approve",headers,{}).status)
        approved=self.call("POST",f"/admin/requests/{request['request_id']}/approve",headers,request["approval_challenge"])
        self.assertEqual("simulated",approved.json()["state"])
        self.assertEqual(409,self.call("POST",f"/admin/requests/{request['request_id']}/approve",headers,request["approval_challenge"]).status)
        terminal_panel=self.call("GET","/",{"Cookie":cookie}).body.decode()
        self.assertNotIn("data-id='req_1' data-op='approve'",terminal_panel)
        self.assertNotIn("data-id='req_1' data-op='deny'",terminal_panel)
        paused=self.call("POST","/admin/controls",headers,{"key":"pause_all","value":True})
        self.assertTrue(paused.json()["pause_all"])
        loopback={"Cookie":cookie,"Origin":"http://127.0.0.1:18790","X-CSRF-Token":csrf}
        resumed=self.call("POST","/admin/controls",loopback,{"key":"pause_all","value":False})
        self.assertFalse(resumed.json()["pause_all"])
        lowercase={"cookie":cookie,"origin":"https://control.example","x-csrf-token":csrf}
        case_insensitive=self.call("POST","/admin/controls",lowercase,{"key":"pause_all","value":True})
        self.assertEqual(200,case_insensitive.status)
        self.assertTrue(case_insensitive.json()["pause_all"])

    def test_emergency_controls_need_no_javascript(self):
        login=self.call("POST","/login",payload={"username":"control","password":"correct horse battery staple"})
        cookie=login.headers["Set-Cookie"].split(";",1)[0]
        panel=self.call("GET","/",{"Cookie":cookie}).body.decode()
        self.assertNotIn("<script",panel)
        self.assertNotIn("data-control=",panel)
        self.assertNotIn("prompt(",panel)
        csrf=re.search(r"name='csrf_token' value='([^']+)'",panel).group(1)
        origin={"Cookie":cookie,"Origin":"https://control.example"}
        self.assertEqual(403,self.form("POST","/admin/controls",{"Cookie":cookie},{"csrf_token":csrf,"key":"pause_all","value":"true"}).status)
        paused=self.form("POST","/admin/controls",origin,{"csrf_token":csrf,"key":"pause_all","value":"true"})
        self.assertEqual(303,paused.status); self.assertEqual("/",paused.headers["Location"])
        self.assertTrue(self.ledger.controls()["pause_all"])
        self.assertEqual(303,self.form("POST","/admin/controls",origin,{"csrf_token":csrf,"key":"pause_all","value":"false"}).status)
        self.assertFalse(self.ledger.controls()["pause_all"])
        self.form("POST","/admin/controls",origin,{"csrf_token":csrf,"key":"paused_domains","value":"device, purchase"})
        self.assertEqual(["device","purchase"],self.ledger.controls()["paused_domains"])
        self.form("POST","/admin/controls",origin,{"csrf_token":csrf,"key":"paused_domains","value":""})
        self.assertEqual([],self.ledger.controls()["paused_domains"])
        for invalid in ({"key":"pause_all","value":"maybe"},{"key":"unknown_key","value":"true"}):
            with self.subTest(invalid=invalid):
                self.assertEqual(400,self.form("POST","/admin/controls",origin,{"csrf_token":csrf,**invalid}).status)

    def test_panel_shows_durable_notification_delivery_and_recovery_status(self):
        login=self.call("POST","/login",payload={"username":"control","password":"correct horse battery staple"})
        cookie=login.headers["Set-Cookie"].split(";",1)[0]
        request=self.call("POST","/api/v1/requests",self.agent,{"action":"device.power_off","parameters":{},"context":{},"idempotency_key":"notice-status"}).json()
        self.ledger.enqueue_notification(request_id=request["request_id"],request_hash=request["request_hash"],notify_gate_id="notify",recipient="owner",template_hash="a"*64,now=100)
        panel=self.call("GET","/",{"Cookie":cookie}).body.decode()
        self.assertIn("Notification queued",panel)
        self.assertIn("will retry after provider recovery",panel)
        self.assertIn("notice_",panel)

    def test_health_and_panel_surface_provider_outage_status(self):
        self.app.status_provider=lambda:{"notification_outbox":{"pending":2,"unknown":1,"oldest_pending_at":90},"relay":{"status":"outage","last_success_at":80,"last_error":"provider unavailable"}}
        health=self.call("GET","/health").json()
        self.assertEqual("outage",health["relay"]["status"])
        self.assertEqual(2,health["notification_outbox"]["pending"])
        login=self.call("POST","/login",payload={"username":"control","password":"correct horse battery staple"})
        cookie=login.headers["Set-Cookie"].split(";",1)[0]
        panel=self.call("GET","/",{"Cookie":cookie}).body.decode()
        self.assertIn("Provider status: outage",panel)
        self.assertIn("2 pending",panel)
        self.assertIn("1 unknown",panel)

    def test_panel_shows_policy_floor_effective_control_and_step_up_boundary(self):
        login=self.call("POST","/login",payload={"username":"control","password":"correct horse battery staple"})
        cookie=login.headers["Set-Cookie"].split(";",1)[0]
        self.call("POST","/api/v1/requests",self.agent,{"action":"device.power_off","parameters":{},"context":{},"idempotency_key":"step-up-panel","minimum_control":"step_up"})
        text=self.call("GET","/",{"Cookie":cookie}).body.decode()
        self.assertIn("Policy control",text); self.assertIn("Caller floor",text); self.assertIn("Effective control",text)
        self.assertIn("step_up",text); self.assertIn("Step-up required",text)

    def test_control_panel_renders_exact_communication_for_meaningful_approval(self):
        login=self.call("POST","/login",payload={"username":"control","password":"correct horse battery staple"})
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
        self.assertIn("Canonical normalized parameters",text)
        self.assertIn('&quot;details&quot;',text)
        self.assertIn("Request hash",text)
        self.assertIn("h"*64,text)
        self.assertIn("Approval expires at",text)
        self.assertIn("If this request expires, submit a new proposal",text)

    def test_panel_leads_with_pending_decision_work_that_needs_no_javascript(self):
        login=self.call("POST","/login",payload={"username":"control","password":"correct horse battery staple"})
        cookie=login.headers["Set-Cookie"].split(";",1)[0]; csrf=login.headers["X-CSRF-Token"]
        pending=self.call("POST","/api/v1/requests",self.agent,{"action":"device.power_off","parameters":{"summary":"free text written by the model","target":"example-display","details":{}},"context":{},"idempotency_key":"pending display"}).json()
        self.ledger.enqueue_notification(request_id=pending["request_id"],request_hash=pending["request_hash"],notify_gate_id="notify",recipient="human_owner",template_hash="a"*64,now=90)
        history=self.call("POST","/api/v1/requests",self.agent,{"action":"device.power_off","parameters":{"summary":"already decided","target":"example-display","details":{}},"context":{},"idempotency_key":"history one"}).json()
        denied=self.call("POST",f"/admin/requests/{history['request_id']}/deny",{"Cookie":cookie,"Origin":"https://control.example","X-CSRF-Token":csrf},history["approval_challenge"])
        self.assertEqual("denied",denied.json()["state"])
        text=self.call("GET","/",{"Cookie":cookie}).body.decode()

        # Pending decisions come first; decided work is demoted to secondary history.
        self.assertLess(text.index("Pending decisions (1)"),text.index(pending["request_id"]))
        self.assertLess(text.index(pending["request_id"]),text.index("Completed history"))
        self.assertIn(history["request_id"],text[text.index("Completed history"):])

        card=text[text.index("Pending decisions (1)"):text.index("Completed history")]
        for expected in ("device.power_off","Power off the allowlisted meeting-room display","Display is idle outside booked hours",
                         "Safe target","example-display","Requester","agent","node-example-1","Risk","R2",
                         "Policy control","Caller floor","Effective control","Expires","in 5 min",
                         "Notification queued","Approve once","Deny"):
            with self.subTest(expected=expected): self.assertIn(expected,card)

        # Accessible landmarks, headings, responsive layout and visible focus.
        for expected in ("<html lang=en>","name=viewport","Skip to pending decisions","<main","<h1","<h2","aria-labelledby","@media","focus-visible"):
            with self.subTest(expected=expected): self.assertIn(expected,text)

        # No JavaScript anywhere on the critical decision surface.
        self.assertNotIn("<script",text); self.assertNotIn("javascript:",text); self.assertNotIn("onclick",text)

        # Approve/deny remain exact ordinary POST forms bound to the immutable challenge.
        self.assertIn(f"action='/admin/requests/{pending['request_id']}/approve'",card)
        self.assertIn(f"action='/admin/requests/{pending['request_id']}/deny'",card)
        self.assertIn(f"name='request_hash' value='{'h'*64}'",card)
        fields={key:str(value) for key,value in pending["approval_challenge"].items()}
        form_csrf=re.search(r"name='csrf_token' value='([^']+)'",card).group(1)
        self.assertEqual(403,self.form("POST",f"/admin/requests/{pending['request_id']}/approve",{"Cookie":cookie},{"csrf_token":form_csrf,**fields}).status)
        self.assertEqual(403,self.form("POST",f"/admin/requests/{pending['request_id']}/approve",{"Cookie":cookie,"Origin":"https://evil.example"},{"csrf_token":form_csrf,**fields}).status)
        self.assertEqual(403,self.form("POST",f"/admin/requests/{pending['request_id']}/approve",{"Cookie":cookie,"Origin":"https://control.example"},{"csrf_token":"wrong",**fields}).status)
        self.assertEqual(409,self.form("POST",f"/admin/requests/{pending['request_id']}/approve",{"Cookie":cookie,"Origin":"https://control.example"},{"csrf_token":form_csrf,**fields,"request_hash":"g"*64}).status)
        approved=self.form("POST",f"/admin/requests/{pending['request_id']}/approve",{"Cookie":cookie,"Origin":"https://control.example"},{"csrf_token":form_csrf,**fields})
        self.assertEqual(303,approved.status)
        self.assertEqual("simulated",self.control.backend.requests[pending["request_id"]]["state"])

    def test_pending_card_withholds_message_bodies_that_only_the_exact_review_shows(self):
        self.app.catalog={"actions":{"communication.send":{"risk":"R3","effect":"write","summary":"Send one reviewed message","presentation":{"proposed_effect":"Send one email to the reviewed supplier address","reason":"The purchase needs written supplier confirmation","node":"node-example-2","safe_target_field":"target","safe_target_values":["support@example.test"],"spends":False,"communicates":True,"changes_state":False}}}}
        login=self.call("POST","/login",payload={"username":"control","password":"correct horse battery staple"})
        cookie=login.headers["Set-Cookie"].split(";",1)[0]
        parameters={"summary":"Email supplier before purchase","target":"support@example.test","details":{"channel":"email","recipient":"support@example.test","subject":"Exact component confirmation","body":"Hello supplier,\nPlease confirm parts.","listing_id":"LIST-123","attachments":["requirements.pdf"]}}
        self.call("POST","/api/v1/requests",self.agent,{"action":"communication.send","parameters":parameters,"context":{},"idempotency_key":"card leakage"})
        text=self.call("GET","/",{"Cookie":cookie}).body.decode()
        card=text[text.index("Pending decisions (1)"):text.index("<details class=request-review")]
        for expected in ("Send one email to the reviewed supplier address","support@example.test","The purchase needs written supplier confirmation","Can communicate externally","R3"):
            with self.subTest(expected=expected): self.assertIn(expected,card)
        for leaked in ("Hello supplier","Please confirm parts","LIST-123","requirements.pdf","Exact component confirmation","Email supplier before purchase","Canonical normalized parameters"):
            with self.subTest(leaked=leaked): self.assertNotIn(leaked,card)
        self.assertIn("Hello supplier,",text)
        self.assertIn("Canonical normalized parameters",text)

    def test_panel_is_responsive_and_keyboard_accessible(self):
        login=self.call("POST","/login",payload={"username":"control","password":"correct horse battery staple"})
        cookie=login.headers["Set-Cookie"].split(";",1)[0]
        text=self.call("GET","/",{"Cookie":cookie}).body.decode()
        for expected in ("<html lang=en>","<meta charset=utf-8>","name=viewport","class=skip href='#pending'",
                         "@media (max-width:640px)",":focus-visible","<th scope=col>","<label for=paused-domains>",
                         "min-height:44px"):
            with self.subTest(expected=expected): self.assertIn(expected,text)
        self.assertNotIn("min-width:min(620px,75vw)",text)
        self.assertEqual(1,text.count("<h1"))
        login_page=self.call("GET","/login").body.decode()
        self.assertIn("<html lang=en>",login_page); self.assertIn(":focus-visible",login_page)
        self.assertIn("<label for=username>",login_page); self.assertIn("<label for=password>",login_page)

    def test_panel_palette_meets_wcag_contrast(self):
        def channel(value):
            value/=255
            return value/12.92 if value<=0.04045 else ((value+0.055)/1.055)**2.4
        def luminance(colour):
            red,green,blue=(channel(int(colour[index:index+2],16)) for index in (1,3,5))
            return 0.2126*red+0.7152*green+0.0722*blue
        rendered=self.call("GET","/login").body.decode()
        for foreground,background in PANEL_CONTRAST_PAIRS:
            with self.subTest(pair=(foreground,background)):
                first,second=luminance(PANEL_COLORS[foreground]),luminance(PANEL_COLORS[background])
                ratio=(max(first,second)+0.05)/(min(first,second)+0.05)
                self.assertGreaterEqual(ratio,4.5)
        for colour in PANEL_COLORS.values():
            with self.subTest(colour=colour): self.assertRegex(colour,r"^#[0-9a-f]{6}$")
        self.assertIn(PANEL_COLORS["page"],rendered)

    def standing_policy(self):
        return AutoApprovalPolicy({"version":7,"enabled":True,"rules":[],"global_simulation_rule":{
            "rule_id":"rule-global-simulation","version":1,"prohibited_classes":sorted(PROHIBITED_CLASSES),
            "requesters":["agent"],"nodes":["node-example-1"],"expires_at":90_000,"review_by":80_000}})

    def test_panel_shows_the_global_standing_rule_simulation_stop_and_prohibited_floor(self):
        self.app.auto_approval=self.standing_policy()
        login=self.call("POST","/login",payload={"username":"control","password":"correct horse battery staple"})
        cookie=login.headers["Set-Cookie"].split(";",1)[0]
        panel=self.call("GET","/",{"Cookie":cookie}).body.decode()
        for expected in ("GLOBAL AUTO-APPROVE","simulation only","execution_enabled=false","Auto-approval rules",
                         "rule-global-simulation","version 1","Enabled","Next review","Expires",
                         "Always asks a human","Pause auto-approval",
                         "credentials","spending","external_communication","destructive_git",
                         "undeclared_infrastructure","arbitrary_command"):
            with self.subTest(expected=expected): self.assertIn(expected,panel)
        self.assertNotIn("<script",panel)
        csrf=re.search(r"name='csrf_token' value='([^']+)'",panel).group(1)
        origin={"Cookie":cookie,"Origin":"https://control.example"}
        self.assertEqual(403,self.form("POST","/admin/controls",{"Cookie":cookie},{"csrf_token":csrf,"key":"auto_approval_paused","value":"true"}).status)
        paused=self.form("POST","/admin/controls",origin,{"csrf_token":csrf,"key":"auto_approval_paused","value":"true"})
        self.assertEqual(303,paused.status)
        self.assertIs(True,self.ledger.controls()["auto_approval_paused"])
        self.assertIn("Auto-approval is paused",self.call("GET","/",{"Cookie":cookie}).body.decode())
        self.form("POST","/admin/controls",origin,{"csrf_token":csrf,"key":"disabled_auto_rules","value":"rule-global-simulation"})
        self.assertIn("Disabled",self.call("GET","/",{"Cookie":cookie}).body.decode())
        self.form("POST","/admin/controls",origin,{"csrf_token":csrf,"key":"auto_approval_paused","value":"false"})
        self.assertIs(False,self.ledger.controls()["auto_approval_paused"])

    def test_agents_cannot_reach_any_auto_approval_rule_mutation_surface(self):
        self.app.auto_approval=self.standing_policy()
        tools=[tool["name"] for tool in self.call("POST","/mcp",self.agent,{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}).json()["result"]["tools"]]
        self.assertEqual(["list_actions","explain_action","request_action","get_request","cancel_request"],tools)
        for path in ("/api/v1/auto-approval-rules","/api/v1/auto-approval/pause","/admin/auto-approval-rules"):
            with self.subTest(path=path):
                self.assertIn(self.call("POST",path,self.agent,{"enabled":True}).status,{403,404})
        self.assertEqual(403,self.call("POST","/admin/controls",self.agent,{"key":"auto_approval_paused","value":False}).status)
        self.assertEqual(403,self.form("POST","/admin/controls",{},{"key":"auto_approval_paused","value":"false"}).status)
        self.assertIs(False,self.ledger.controls()["auto_approval_paused"])

    def test_pending_card_explains_why_auto_approval_did_not_apply(self):
        self.control.backend.auto_decision={"matched":False,"reason_code":"prohibited_class_requires_human",
                                            "reason":"The action falls inside the prohibited safety floor. (class: spending)"}
        login=self.call("POST","/login",payload={"username":"control","password":"correct horse battery staple"})
        cookie=login.headers["Set-Cookie"].split(";",1)[0]
        self.call("POST","/api/v1/requests",self.agent,{"action":"device.power_off","parameters":{},"context":{},"idempotency_key":"dry run"})
        panel=self.call("GET","/",{"Cookie":cookie}).body.decode()
        card=panel[panel.index("Pending decisions (1)"):panel.index("<details class=request-review")]
        self.assertIn("Auto-approval did not apply",card)
        self.assertIn("prohibited safety floor",card)
        self.assertIn("spending",card)

    def test_panel_separates_gate_decisions_policy_denials_and_execution_telemetry(self):
        login=self.call("POST","/login",payload={"username":"control","password":"correct horse battery staple"})
        cookie=login.headers["Set-Cookie"].split(";",1)[0]; csrf=login.headers["X-CSRF-Token"]
        pending=self.call("POST","/api/v1/requests",self.agent,{"action":"device.power_off","parameters":{},"context":{},"idempotency_key":"feed pending"}).json()
        observation={"event_id":"call-1","correlation_id":"corr-1","phase":"completed","operation":"code.edit_file",
                     "semantic_class":"code.change.write","outcome":"failed","occurred_at":99,
                     "metadata":{"surface":"harness","error_type":"nonzero_exit"}}
        self.call("POST","/api/v1/audit-observations",self.agent,observation)
        self.call("POST","/api/v1/audit-observations",self.agent,{**observation,"event_id":"call-1-detail","occurred_at":100})
        panel=self.call("GET","/",{"Cookie":cookie}).body.decode()
        self.assertLess(panel.index("Pending decisions (1)"),panel.index("Policy denials (0)"))
        self.assertIn("Execution telemetry (1)",panel)
        self.assertIn("Gate errors (0)",panel)
        self.assertIn("?feed=denials",panel); self.assertIn("?feed=telemetry",panel)
        self.assertIn("Ordinary tool failures, timeouts, interrupts and cancellations are not Semantic Gate decisions",panel)
        self.assertIn("Coordinator health",panel)
        self.assertIn("<summary>Full audit ledger</summary>",panel)
        telemetry=self.call("GET","/?feed=telemetry",{"Cookie":cookie}).body.decode()
        self.assertIn("tool exited with a nonzero exit status",telemetry)
        self.assertIn("tool telemetry",telemetry)
        self.assertIn("call-1, call-1-detail",telemetry)
        self.assertIn("occurrences 2",telemetry)
        self.assertNotIn("tool exited with a nonzero exit status",panel)
        denied=self.call("POST",f"/admin/requests/{pending['request_id']}/deny",{"Cookie":cookie,"Origin":"https://control.example","X-CSRF-Token":csrf},pending["approval_challenge"])
        self.assertEqual("denied",denied.json()["state"])
        denials=self.call("GET","/?feed=denials",{"Cookie":cookie}).body.decode()
        self.assertIn("Policy denials (1)",denials)
        self.assertIn("denied by a human decision",denials)
        self.assertIn("policy gate",denials)
        self.assertNotIn("tool exited",denials)
        self.assertEqual(400,self.call("GET","/?feed=../etc",{"Cookie":cookie}).status)

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
