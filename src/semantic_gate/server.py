#!/usr/bin/env python3
"""Generic HTTP/MCP application and mobile control panel."""
from __future__ import annotations

import hashlib
import hmac
import html
import json
from dataclasses import dataclass
from http import cookies
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from . import __version__
from .auth import AuthError, CapabilityAuthority, Principal
from .controller import GateControl, GateControlError
from .credentials import CredentialRegistry
from .engine import GatePolicyError, _validate_json_value


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self):
        return json.loads(self.body)


def _json(status: int, value: Any, headers: dict[str, str] | None = None) -> Response:
    base={"Content-Type":"application/json","Cache-Control":"no-store"}; base.update(headers or {})
    return Response(status,base,json.dumps(value,sort_keys=True,separators=(",", ":"),allow_nan=False).encode())


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted=name.casefold()
    return next((value for key,value in headers.items() if key.casefold()==wanted),None)


def _request_review(request: Mapping[str, Any]) -> str:
    parameters=request.get("parameters")
    if not isinstance(parameters,Mapping): parameters={}
    details=parameters.get("details")
    if not isinstance(details,Mapping): details={}
    def value(label: str, item: Any) -> str:
        if item in (None,"",[],{}): return ""
        rendered=item if isinstance(item,str) else json.dumps(item,ensure_ascii=False,sort_keys=True)
        return f"<dt>{html.escape(label)}</dt><dd>{html.escape(rendered)}</dd>"
    fields="".join(filter(None,(
        value("Summary",parameters.get("summary")),
        value("Target",parameters.get("target")),
        value("Channel",details.get("channel")),
        value("Recipient",details.get("recipient")),
        value("Subject",details.get("subject")),
        value("Listing ID",details.get("listing_id")),
        value("Attachments",details.get("attachments")),
    )))
    message=details.get("body")
    message_html=f"<h4>Message body</h4><pre class=message>{html.escape(message)}</pre>" if isinstance(message,str) and message else ""
    open_attr=" open" if request.get("state")=="waiting_for_approval" else ""
    return f"<details class=request-review{open_attr}><summary>Review exact request</summary><dl>{fields}</dl>{message_html}</details>"


MCP_TOOLS = [
    {"name":"list_actions","description":"List semantic actions this principal may propose.","inputSchema":{"type":"object","properties":{},"additionalProperties":False}},
    {"name":"explain_action","description":"Explain one action and its deterministic gates.","inputSchema":{"type":"object","properties":{"action":{"type":"string"}},"required":["action"],"additionalProperties":False}},
    {"name":"request_action","description":"Propose an action; Semantic Gate decides required control. Caller may set only a stricter minimum_control floor and cannot approve or execute.","inputSchema":{"type":"object","properties":{"action":{"type":"string"},"parameters":{"type":"object"},"context":{"type":"object"},"idempotency_key":{"type":"string"},"minimum_control":{"type":"string","enum":["policy","ask","step_up"],"default":"policy"}},"required":["action","parameters","context","idempotency_key"],"additionalProperties":False}},
    {"name":"get_request","description":"Get one request owned by this principal.","inputSchema":{"type":"object","properties":{"request_id":{"type":"string"}},"required":["request_id"],"additionalProperties":False}},
    {"name":"cancel_request","description":"Restrictively cancel one owned pending request.","inputSchema":{"type":"object","properties":{"request_id":{"type":"string"}},"required":["request_id"],"additionalProperties":False}},
]


class SemanticGateApplication:
    def __init__(self, control: GateControl, authority: CapabilityAuthority, credentials: CredentialRegistry, *, catalog: Mapping[str, Any], admin_password: str, admin_principal_id: str = "control", origins: Sequence[str], clock, secure_cookies: bool = True):
        self.control=control; self.authority=authority; self.credentials=credentials
        self.catalog=dict(catalog); self.admin_password=admin_password; self.admin_principal_id=admin_principal_id; self.clock=clock; self.secure_cookies=secure_cookies
        self.origins=frozenset(origin.rstrip("/") for origin in origins)
        if not self.origins or any(urlsplit(origin).scheme not in {"http","https"} or not urlsplit(origin).netloc or urlsplit(origin).path for origin in self.origins):
            raise ValueError("origins must be exact HTTP(S) origins without paths")

    @staticmethod
    def _decode(body: bytes) -> dict:
        if len(body)>1_048_576: raise GateControlError("request body is too large")
        try: value=json.loads(body or b"{}",parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        except (json.JSONDecodeError,UnicodeDecodeError) as error: raise GateControlError("invalid JSON") from error
        if not isinstance(value,dict): raise GateControlError("JSON body must be an object")
        try: _validate_json_value(value)
        except GatePolicyError as error: raise GateControlError(str(error)) from error
        return value

    def _bearer(self, headers: Mapping[str,str]) -> Principal:
        return self.authority.authenticate_bearer(_header(headers,"Authorization"))

    def _action_bearer(self, headers: Mapping[str,str]) -> Principal:
        principal=self._bearer(headers)
        if principal.role=="observer": raise PermissionError("observer principal is audit-only")
        return principal

    @staticmethod
    def _cookie(headers: Mapping[str,str], name: str) -> str | None:
        jar=cookies.SimpleCookie(); jar.load(_header(headers,"Cookie") or ""); morsel=jar.get(name)
        return morsel.value if morsel else None

    def _admin(self, headers: Mapping[str,str]) -> tuple[Principal,str]:
        session=self._cookie(headers,"sg_session")
        if not session: raise AuthError("admin session is required")
        principal=self.authority.verify_session(session,now=int(self.clock()))
        if principal.role!="admin": raise AuthError("admin session is required")
        return principal,session

    @staticmethod
    def _csrf(session: str) -> str:
        return hashlib.sha256(("semantic-gate-csrf\0"+session).encode()).hexdigest()

    def _require_mutation(self, headers: Mapping[str,str]) -> Principal:
        principal,session=self._admin(headers)
        if (_header(headers,"Origin") or "").rstrip("/") not in self.origins or not hmac.compare_digest(_header(headers,"X-CSRF-Token") or "",self._csrf(session)):
            raise AuthError("origin or CSRF validation failed")
        return principal

    def _panel(self, session: str) -> Response:
        requests=self.control.list_requests(principal=self.admin_principal_id,admin=True,limit=100)
        controls=self.control.ledger.controls(); actions=self.catalog.get("actions",{})
        audits=self.control.ledger.audit_events(limit=200)
        def decision_buttons(item: Mapping[str,Any]) -> str:
            request_id=html.escape(str(item["request_id"]))
            deny=f"<button data-id='{request_id}' data-op='deny'>Deny</button>"
            if item.get("effective_control")=="step_up":
                return "<button disabled>Step-up required</button> "+deny
            return f"<button data-id='{request_id}' data-op='approve'>Approve once</button> "+deny
        rows="".join(
            f"<tr><td>{html.escape(r['request_id'])}</td><td>{html.escape(r['action'])}</td><td>{html.escape(r['requester'])}</td>"
            f"<td>{html.escape(str(r.get('policy_control','policy')))}</td><td>{html.escape(str(r.get('minimum_control','policy')))}</td>"
            f"<td>{html.escape(str(r.get('effective_control','policy')))}</td><td><b>{html.escape(r['state'])}</b></td>"
            f"<td>{_request_review(r)}</td><td>{decision_buttons(r)}</td></tr>" for r in requests
        )
        action_rows="".join(f"<tr><td><code>{html.escape(a)}</code></td><td>{html.escape(str(v.get('risk','')))}</td><td>{html.escape(str(v.get('effect','')))}</td><td>{html.escape(str(v.get('summary','')))}</td></tr>" for a,v in sorted(actions.items()))
        cred_rows="".join(f"<tr><td>{html.escape(c['credential_id'])}</td><td>{html.escape(c['adapter'])}</td><td>{html.escape(c['status'])}</td></tr>" for c in self.credentials.public_inventory())
        audit_rows="".join(f"<tr><td>{a['seq']}</td><td>{html.escape(str(a['event']))}</td><td>{html.escape(str(a['actor']))}</td><td>{html.escape(str(a.get('request_id') or ''))}</td><td>{a['at']}</td></tr>" for a in audits)
        csrf=self._csrf(session)
        page=f"""<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'><meta name=csrf content='{csrf}'><title>Semantic Gate</title><style>body{{font:15px system-ui;background:#0b1020;color:#edf2ff;margin:0}}main{{max-width:1500px;margin:auto;padding:20px}}section{{background:#151c31;border:1px solid #2b3658;border-radius:14px;padding:16px;margin:14px 0;overflow:auto}}table{{border-collapse:collapse;width:100%}}td,th{{padding:9px;border-bottom:1px solid #2b3658;text-align:left;vertical-align:top}}button{{background:#6ea8fe;color:#07101f;border:0;border-radius:8px;padding:8px;margin:3px}}button.danger{{background:#ff7b72}}code{{color:#9bdcff}}.safe{{color:#85e89d}}.request-review{{min-width:min(620px,75vw)}}.request-review>summary{{font-weight:700;color:#9bdcff;cursor:pointer;padding:8px 0}}dl{{display:grid;grid-template-columns:max-content minmax(220px,1fr);gap:6px 12px}}dt{{color:#aab6d3;font-weight:700}}dd{{margin:0;overflow-wrap:anywhere}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1020;border:1px solid #2b3658;border-radius:8px;padding:10px}}pre.message{{font:14px/1.45 system-ui}}</style><main><h1>Semantic Gate</h1><p class=safe>Execution is globally disabled; decisions simulate only.</p><section><h2>Emergency controls</h2><button class=danger data-control=pause_all data-value=true>Pause all</button><button data-control=pause_all data-value=false>Resume proposals</button><button data-list=paused_domains>Set paused domains</button><button data-list=revoked_principals>Set revoked principals</button><pre>{html.escape(json.dumps(controls,indent=2))}</pre></section><section><h2>Requests</h2><table><tr><th>ID</th><th>Action</th><th>Principal</th><th>Policy control</th><th>Caller floor</th><th>Effective control</th><th>State</th><th>Exact request</th><th>Decision</th></tr>{rows}</table></section><section><h2>Credential bindings</h2><table>{cred_rows}</table></section><section><h2>Action catalogue</h2><table><tr><th>Action</th><th>Risk</th><th>Effect</th><th>Summary</th></tr>{action_rows}</table></section><section><h2>Audit</h2><table><tr><th>#</th><th>Event</th><th>Actor</th><th>Request</th><th>Time</th></tr>{audit_rows}</table></section></main><script>document.addEventListener('click',async e=>{{let path,body={{}};if(e.target.dataset.op)path='/admin/requests/'+e.target.dataset.id+'/'+e.target.dataset.op;else if(e.target.dataset.control){{path='/admin/controls';body={{key:e.target.dataset.control,value:e.target.dataset.value==='true'}}}}else if(e.target.dataset.list){{path='/admin/controls';let raw=prompt('Comma-separated values (empty clears):','');if(raw===null)return;body={{key:e.target.dataset.list,value:raw.split(',').map(x=>x.trim()).filter(Boolean)}}}}else return;let r=await fetch(path,{{method:'POST',headers:{{'Origin':location.origin,'X-CSRF-Token':document.querySelector('meta[name=csrf]').content,'Content-Type':'application/json'}},body:JSON.stringify(body)}});if(r.ok)location.reload();else alert(await r.text())}})</script>"""
        return Response(200,{"Content-Type":"text/html;charset=UTF-8","Cache-Control":"no-store"},page.encode())

    @staticmethod
    def _login_page() -> Response:
        page="""<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'><title>Semantic Gate login</title><style>body{font:16px system-ui;background:#0b1020;color:#edf2ff;display:grid;place-items:center;min-height:100vh}form{background:#151c31;padding:24px;border-radius:14px;border:1px solid #2b3658}label{display:block}input,button{font:inherit;padding:10px;margin:5px;border-radius:8px}button{background:#6ea8fe;border:0}</style><form method=post action=/login><h1>Semantic Gate</h1><label>Username <input name=username type=text autocomplete=username autocapitalize=none spellcheck=false required></label><label>Password <input name=password type=password autocomplete=current-password required autofocus></label><button type=submit>Sign in</button><p id=error></p></form><script>document.querySelector('form').addEventListener('submit',async e=>{e.preventDefault();const data=new FormData(e.target);let r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:data.get('username'),password:data.get('password')})});if(r.ok)location='/';else document.getElementById('error').textContent='Sign-in failed'})</script>"""
        return Response(200,{"Content-Type":"text/html;charset=UTF-8","Cache-Control":"no-store"},page.encode())

    def _mcp(self, principal: Principal, message: dict) -> Response:
        request_id=message.get("id"); method=message.get("method"); params=message.get("params",{})
        try:
            if message.get("jsonrpc")!="2.0" or not isinstance(method,str) or not isinstance(params,dict): raise GateControlError("invalid request")
            if method=="initialize": result={"protocolVersion":"2025-03-26","capabilities":{"tools":{"listChanged":False}},"serverInfo":{"name":"semantic-gate","version":__version__}}
            elif method=="ping": result={}
            elif method=="tools/list": result={"tools":MCP_TOOLS}
            elif method=="tools/call":
                name=params.get("name"); args=params.get("arguments")
                if not isinstance(args,dict): raise GateControlError("tool arguments must be an object")
                if name=="list_actions": value=self.control.list_actions(principal.principal_id)
                elif name=="explain_action": value=self.control.explain_action(args.get("action"),principal.principal_id)
                elif name=="request_action": value=self.control.request_action(principal=principal.principal_id,payload=args,host_context={"surface":"mcp","authenticated_principal":principal.principal_id})
                elif name=="get_request": value=self.control.get_request(args.get("request_id"),principal=principal.principal_id)
                elif name=="cancel_request": value=self.control.cancel(args.get("request_id"),principal=principal.principal_id)
                else: raise GateControlError("unknown MCP tool")
                result={"content":[{"type":"text","text":json.dumps(value,sort_keys=True)}],"structuredContent":value,"isError":False}
            else: return _json(200,{"jsonrpc":"2.0","id":request_id,"error":{"code":-32601,"message":"method not found"}})
            return _json(200,{"jsonrpc":"2.0","id":request_id,"result":result})
        except Exception as error:
            return _json(200,{"jsonrpc":"2.0","id":request_id,"error":{"code":-32602,"message":str(error)}})

    def handle(self, method: str, path: str, headers: Mapping[str,str], body: bytes) -> Response:
        route=urlsplit(path).path
        try:
            if route=="/health" and method=="GET": return _json(200,{"status":"ok","execution_enabled":False})
            if route=="/login" and method=="GET": return self._login_page()
            if route=="/login" and method=="POST":
                supplied=self._decode(body).get("password")
                if not isinstance(supplied,str) or not hmac.compare_digest(supplied,self.admin_password): return _json(403,{"error":"invalid credentials"})
                session=self.authority.issue_session(self.admin_principal_id,now=int(self.clock()),ttl_seconds=3600)
                secure="; Secure" if self.secure_cookies else ""
                return Response(204,{"Set-Cookie":f"sg_session={session}; HttpOnly; SameSite=Strict; Path=/{secure}","X-CSRF-Token":self._csrf(session),"Cache-Control":"no-store"},b"")
            if route=="/" and method=="GET":
                try: _,session=self._admin(headers)
                except AuthError: return Response(303,{"Location":"/login","Cache-Control":"no-store"},b"")
                return self._panel(session)
            if route=="/mcp" and method=="POST": return self._mcp(self._action_bearer(headers),self._decode(body))
            if route=="/api/v1/actions" and method=="GET":
                p=self._action_bearer(headers); return _json(200,self.control.list_actions(p.principal_id))
            if route=="/api/v1/audit-observations" and method=="POST":
                p=self._bearer(headers); return _json(200,self.control.observe(principal=p.principal_id,payload=self._decode(body)))
            if route=="/api/v1/requests" and method=="POST":
                p=self._action_bearer(headers); return _json(201,self.control.request_action(principal=p.principal_id,payload=self._decode(body),host_context={"surface":"http","authenticated_principal":p.principal_id}))
            if route=="/api/v1/requests" and method=="GET":
                p=self._action_bearer(headers); return _json(200,self.control.list_requests(principal=p.principal_id))
            if route.startswith("/api/v1/requests/"):
                p=self._action_bearer(headers); parts=route.strip("/").split("/")
                if len(parts)==4 and method=="GET":
                    return _json(200,self.control.get_request(parts[3],principal=p.principal_id))
                if len(parts)==5 and parts[4]=="cancel" and method=="POST":
                    return _json(200,self.control.cancel(parts[3],principal=p.principal_id))
                return _json(404,{"error":"not found"})
            if route.startswith("/admin/requests/") and method=="POST":
                p=self._require_mutation(headers); parts=route.strip("/").split("/")
                if len(parts)!=4: return _json(404,{"error":"not found"})
                request_id,op=parts[2],parts[3]
                if op=="approve": value=self.control.approve(request_id,actor=p.principal_id,actor_role=p.role)
                elif op=="deny": value=self.control.deny(request_id,actor=p.principal_id,actor_role=p.role)
                else: return _json(404,{"error":"not found"})
                return _json(200,value)
            if route=="/admin/controls" and method=="POST":
                p=self._require_mutation(headers); value=self._decode(body)
                if set(value)!={"key","value"}: raise GateControlError("control body must contain exactly key and value")
                if value["key"]=="pause_all" and type(value["value"]) is not bool: raise GateControlError("pause_all must be boolean")
                if value["key"] in {"paused_domains","revoked_principals"} and (not isinstance(value["value"],list) or any(not isinstance(item,str) or not item for item in value["value"])): raise GateControlError("control list is invalid")
                return _json(200,self.control.set_control(value["key"],value["value"],actor=p.principal_id))
            return _json(404,{"error":"not found"})
        except PermissionError as error: return _json(403,{"error":str(error)})
        except AuthError as error: return _json(401 if route.startswith(("/api/","/mcp")) else 403,{"error":str(error)})
        except (GateControlError,KeyError,ValueError) as error: return _json(400,{"error":str(error)})
