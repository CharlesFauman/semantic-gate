#!/usr/bin/env python3
"""Generic HTTP/MCP application and mobile control panel."""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from http import cookies
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs, urlsplit

from .auth import AuthError, CapabilityAuthority, Principal
from .catalog import HUMAN_GATE_CLASSES
from .controller import GateControl, GateControlError, GateDecisionConflict
from .credentials import CredentialRegistry
from .engine import GatePolicyError, _validate_json_value
from .projection import build_decision_card, collapse_observations, partition_audit_events, render_decision_card_html
from .record import (
    MAX_AUDIT,
    MAX_NOTICES,
    build_semantic_record,
    presentation_safe_text,
    redaction_fingerprint,
    render_semantic_record_html,
    schema_safe_fields,
)


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


# Panel palette. Every pair in PANEL_CONTRAST_PAIRS is asserted against WCAG AA in the tests.
PANEL_COLORS = {
    "page":"#0b1020","surface":"#161d33","text":"#eef2ff","muted":"#c2cbe8","line":"#3a4570",
    "accent":"#9ec5ff","urgent":"#ffcf6b","danger":"#ff9d94","focus":"#ffd479",
    "approve_bg":"#7ee2a8","approve_fg":"#04210f","deny_bg":"#ff9d94","deny_fg":"#2b0703",
}
PANEL_CONTRAST_PAIRS = (
    ("text","page"),("text","surface"),("muted","surface"),("accent","surface"),
    ("urgent","surface"),("danger","surface"),("focus","surface"),
    ("approve_fg","approve_bg"),("deny_fg","deny_bg"),
)


_PANEL_CSS = """*{{box-sizing:border-box}}
body{{font:16px/1.5 system-ui,sans-serif;background:{page};color:{text};margin:0}}
a{{color:{accent}}}
.skip{{position:absolute;left:-9999px}}
.skip:focus{{position:fixed;left:8px;top:8px;z-index:9;background:{surface};color:{text};padding:10px;border:2px solid {focus}}}
main{{max-width:70rem;margin:0 auto;padding:16px}}
h1{{font-size:1.5rem;margin:8px 0}}
h2{{font-size:1.15rem;margin:0 0 12px}}
h3{{font-size:1.05rem;margin:0 0 4px;font-family:ui-monospace,monospace}}
section{{background:{surface};border:1px solid {line};border-radius:10px;padding:16px;margin:12px 0}}
.decision{{border:1px solid {line};border-left:6px solid {accent};border-radius:8px;padding:14px;margin:14px 0}}
.decision.urgent{{border-left-color:{urgent}}}
.decision.expired,.decision.unknown{{border-left-color:{danger}}}
.chip{{font-weight:700;margin:0 0 10px}}
p.banner{{margin:0 0 10px;padding:10px;border:2px solid {urgent};border-radius:8px;color:{urgent};font-weight:600}}
nav.feeds{{display:flex;flex-wrap:wrap;gap:14px;margin:0 0 12px}}
.chip.urgent{{color:{urgent}}}
.chip.expired,.chip.unknown{{color:{danger}}}
dl.facts{{display:grid;grid-template-columns:15rem minmax(0,1fr);gap:6px 14px;margin:0 0 12px}}
dt{{color:{muted};font-weight:600}}
dd{{margin:0;overflow-wrap:anywhere}}
p.consequence{{margin:4px 0}}
.actions{{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0}}
.actions form{{margin:0}}
button{{font:inherit;font-weight:700;min-height:44px;padding:12px 18px;border:0;border-radius:8px;cursor:pointer;background:{approve_bg};color:{approve_fg}}}
button.danger{{background:{deny_bg};color:{deny_fg}}}
button[disabled]{{background:{line};color:{text};cursor:not-allowed}}
:focus-visible{{outline:3px solid {focus};outline-offset:2px}}
label{{display:block;color:{muted};margin:10px 0 4px}}
input[type=text]{{font:inherit;width:min(100%,26rem);padding:10px;border:1px solid {line};border-radius:8px;background:{page};color:{text}}}
table{{border-collapse:collapse;width:100%}}
caption{{text-align:left;padding-bottom:8px}}
th,td{{padding:8px;border-bottom:1px solid {line};text-align:left;vertical-align:top}}
code{{font-family:ui-monospace,monospace;color:{accent};overflow-wrap:anywhere}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:{page};border:1px solid {line};border-radius:8px;padding:10px}}
.muted{{color:{muted}}}
.warn{{color:{urgent};font-weight:700}}
summary{{cursor:pointer;font-weight:700;color:{accent};padding:6px 0}}
details.request-review dl{{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:6px 12px}}
@media (max-width:640px){{main{{padding:10px}}dl.facts{{grid-template-columns:1fr;gap:0}}dt{{margin-top:10px}}
.actions{{flex-direction:column}}.actions form,.actions button{{width:100%}}section{{padding:12px}}
table{{display:block;overflow-x:auto}}}}""".format(**PANEL_COLORS)


_LOGIN_CSS = """body{{font:16px/1.5 system-ui,sans-serif;background:{page};color:{text};margin:0}}
main{{display:grid;place-items:center;min-height:100vh;padding:16px}}
form{{background:{surface};border:1px solid {line};border-radius:10px;padding:24px;width:min(100%,24rem)}}
h1{{font-size:1.4rem;margin:0 0 12px}}
label{{display:block;color:{muted};margin:12px 0 4px}}
input{{font:inherit;width:100%;padding:12px;border:1px solid {line};border-radius:8px;background:{page};color:{text}}}
button{{font:inherit;font-weight:700;width:100%;min-height:44px;margin-top:16px;padding:12px;border:0;border-radius:8px;background:{approve_bg};color:{approve_fg};cursor:pointer}}
:focus-visible{{outline:3px solid {focus};outline-offset:2px}}""".format(**PANEL_COLORS)


def _utc(value: Any) -> str:
    if type(value) is not int: return "unknown"
    return datetime.fromtimestamp(value,tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Stable detail routes are keyed by exact request identifiers only.
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


MCP_TOOLS = [
    {"name":"list_actions","description":"List semantic actions this principal may propose.","inputSchema":{"type":"object","properties":{},"additionalProperties":False}},
    {"name":"explain_action","description":"Explain one action and its deterministic gates.","inputSchema":{"type":"object","properties":{"action":{"type":"string"}},"required":["action"],"additionalProperties":False}},
    {"name":"request_action","description":"Propose an action; Semantic Gate decides required control. Caller may set only a stricter minimum_control floor and cannot approve or execute.","inputSchema":{"type":"object","properties":{"action":{"type":"string"},"parameters":{"type":"object"},"context":{"type":"object"},"idempotency_key":{"type":"string"},"minimum_control":{"type":"string","enum":["policy","ask","step_up"],"default":"policy"}},"required":["action","parameters","context","idempotency_key"],"additionalProperties":False}},
    {"name":"get_request","description":"Get one request owned by this principal.","inputSchema":{"type":"object","properties":{"request_id":{"type":"string"}},"required":["request_id"],"additionalProperties":False}},
    {"name":"cancel_request","description":"Restrictively cancel one owned pending request.","inputSchema":{"type":"object","properties":{"request_id":{"type":"string"}},"required":["request_id"],"additionalProperties":False}},
]


class SemanticGateApplication:
    FEEDS = ("decisions","denials","gate_errors","withdrawn","telemetry")
    FEED_LABELS = {"decisions":"Gate decisions","denials":"Policy denials","gate_errors":"Gate errors",
                   "withdrawn":"Withdrawn or expired","telemetry":"Execution telemetry"}
    HISTORY_STATES = ("all","simulated","executed","denied","blocked","cancelled","expired","failed")
    PANEL_QUERY_PARAMS = frozenset({"feed","state","page","pending_page"})
    HISTORY_PAGE_SIZE = 50
    PENDING_PAGE_SIZE = 50
    # Fail-closed serialized byte bounds enforced before any panel/detail response.
    PANEL_MAX_BYTES = 4_000_000
    DETAIL_MAX_BYTES = 1_000_000

    def __init__(self, control: GateControl, authority: CapabilityAuthority, credentials: CredentialRegistry, *, catalog: Mapping[str, Any], admin_password: str, admin_principal_id: str = "control", origins: Sequence[str], clock, secure_cookies: bool = True, status_provider=None, principal_contexts: Mapping[str, Mapping[str, Any]] | None = None):
        self.control=control; self.authority=authority; self.credentials=credentials
        self.catalog=dict(catalog); self.admin_password=admin_password; self.admin_principal_id=admin_principal_id; self.clock=clock; self.secure_cookies=secure_cookies
        self.principal_contexts={str(key):dict(value) for key,value in (principal_contexts or {}).items()}
        self.status_provider=status_provider or (lambda:{})
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

    def _require_mutation(self, headers: Mapping[str,str], *, csrf_token: str | None=None) -> Principal:
        principal,session=self._admin(headers)
        supplied=_header(headers,"X-CSRF-Token") or csrf_token or ""
        if (_header(headers,"Origin") or "").rstrip("/") not in self.origins or not hmac.compare_digest(supplied,self._csrf(session)):
            raise AuthError("origin or CSRF validation failed")
        return principal

    @staticmethod
    def _form(body: bytes) -> dict[str,str]:
        try:
            decoded=body.decode("utf-8","strict")
            values=parse_qs(decoded,keep_blank_values=True,strict_parsing=True,max_num_fields=16)
        except (UnicodeDecodeError,ValueError) as error:
            raise GateControlError("invalid form body") from error
        if any(len(items)!=1 for items in values.values()):
            raise GateControlError("duplicate form field")
        return {key:items[0] for key,items in values.items()}

    def _hidden(self, fields: Mapping[str,Any]) -> str:
        return "".join(f"<input type=hidden name='{html.escape(str(key),quote=True)}' value='{html.escape(str(value),quote=True)}'>" for key,value in fields.items())

    def _decision_controls(self, item: Mapping[str,Any], *, csrf: str, card: Mapping[str,Any]) -> str:
        if not card["decision_available"]:
            if card["urgency"]=="expired":
                return "<p class=warn><b>Approval expired.</b> Submit a new proposal; this request cannot be revived.</p>"
            return "<p class=warn>Decision unavailable; refresh or submit a new proposal.</p>"
        request_id=html.escape(str(item.get("request_id","")),quote=True)
        hidden=self._hidden({"csrf_token":csrf,**dict(card["reaction_binding"])})
        deny=f"<form method=post action='/admin/requests/{request_id}/deny'>{hidden}<button class=danger type=submit>Deny</button></form>"
        if item.get("effective_control")=="step_up":
            return f"<div class=actions><button disabled>Step-up required</button>{deny}</div><p class=muted>Step-up assurance needs an independently authenticated stronger transport.</p>"
        approve=f"<form method=post action='/admin/requests/{request_id}/approve'>{hidden}<button type=submit>Approve once</button></form>"
        return f"<div class=actions>{approve}{deny}</div>"

    def _request_review(self, request: Mapping[str,Any]) -> str:
        """Sanitized review fragment. A detail field renders as screened text only
        when the checked-in catalogue schema explicitly marks that field
        presentation-safe; every other value - recipients, attachment names,
        subjects and bodies included - appears solely as an explicit redaction
        fingerprint. No raw parameter values."""
        parameters=request.get("parameters")
        if not isinstance(parameters,Mapping): parameters={}
        details=parameters.get("details")
        if not isinstance(details,Mapping): details={}
        actions=self.catalog.get("actions")
        entry=actions.get(request.get("action")) if isinstance(actions,Mapping) else None
        safe=schema_safe_fields(entry if isinstance(entry,Mapping) else {})
        def row(label: str, rendered: Any) -> str:
            if not rendered: return ""
            return f"<dt>{html.escape(label)}</dt><dd>{html.escape(str(rendered))}</dd>"
        def screened(label: str, name: str, item: Any, limit: int = 160) -> str:
            if not isinstance(item,str) or not item: return ""
            if name in safe:
                rendered=presentation_safe_text(item,limit=limit)
                if rendered is not None: return row(label,rendered)
            return row(label,redaction_fingerprint(item,f"{label.casefold()} is not schema-marked presentation-safe"))
        def fingerprint(label: str, item: Any) -> str:
            if not isinstance(item,str) or not item: return ""
            return row(label,redaction_fingerprint(item,f"{label.casefold()} content"))
        attachments=details.get("attachments")
        attachment_names=[]
        for item in (attachments if isinstance(attachments,(list,tuple)) else ())[:8]:
            if not isinstance(item,str) or not item: continue
            rendered=presentation_safe_text(item) if "attachments" in safe else None
            attachment_names.append(rendered if rendered is not None
                                    else redaction_fingerprint(item,"attachment name is not schema-marked presentation-safe"))
        fields="".join(filter(None,(
            screened("Channel","channel",details.get("channel"),limit=32),
            screened("Recipient","recipient",details.get("recipient")),
            screened("Listing ID","listing_id",details.get("listing_id"),limit=64),
            row("Attachments","; ".join(attachment_names)),
            # Message content is never schema-authorizable on this surface.
            fingerprint("Subject",details.get("subject")),
            fingerprint("Message body",details.get("body")),
        )))
        raw_challenge=request.get("approval_challenge")
        challenge=raw_challenge if isinstance(raw_challenge,Mapping) else {}
        expiry=challenge.get("expires_at","")
        binding=(
            "<p class=muted>Message and parameter content is withheld; only redaction fingerprints are shown. "
            "The full sanitized semantic record below is the complete review surface.</p>"
            f"<dl><dt>Request hash</dt><dd><code>{html.escape(str(request.get('request_hash','')))}</code></dd>"
            f"<dt>Approval expires at</dt><dd>{html.escape(str(expiry))}</dd></dl>"
            "<p>If this request expires, submit a new proposal; never reuse an old decision.</p>"
        )
        return f"<details class=request-review><summary>Review exact request</summary><dl>{fields}</dl>{binding}</details>"

    def _semantic_record(self, item: Mapping[str,Any], observations=None) -> dict:
        """Build the complete sanitized semantic record for one request snapshot."""
        request_id=str(item.get("request_id") or "")
        # Fetch one past each record cap (storage-level LIMIT) so the record can
        # mark truncation explicitly without ever materializing the full table.
        audit=self.control.ledger.audit_events(request_id,limit=MAX_AUDIT+1) if request_id else []
        notices=(self.control.ledger.notifications_for_request(request_id,limit=MAX_NOTICES+1)
                 if request_id else [])
        if observations is None:
            observations=self.control.ledger.recent_observations(limit=200)
        telemetry=[row for row in observations
                   if isinstance(row,Mapping) and request_id and row.get("correlation_id")==request_id]
        node=self.principal_contexts.get(str(item.get("requester") or ""),{}).get("node")
        return build_semantic_record(item,catalog=self.catalog,node=node,
                                     audit_events=audit,notifications=notices,telemetry=telemetry)

    def _record_details(self, item: Mapping[str,Any], observations=None) -> str:
        """Expandable, escaped Full-semantic-record fragment with its stable detail link."""
        record=self._semantic_record(item,observations)
        request_id=str(item.get("request_id") or "")
        href=f"/admin/requests/{request_id}" if _REQUEST_ID.fullmatch(request_id) else None
        return render_semantic_record_html(record,detail_href=href)

    def _request_detail(self, request_id: str) -> Response:
        """Stable authenticated detail page keyed by request ID; sanitized record only."""
        if not _REQUEST_ID.fullmatch(request_id):
            return _json(404,{"error":"not found"})
        try:
            item=self.control.get_request(request_id,principal=self.admin_principal_id,admin=True)
        except (GateControlError,KeyError,ValueError):
            return _json(404,{"error":"request not found"})
        fragment=render_semantic_record_html(self._semantic_record(item),open_by_default=True)
        safe_id=html.escape(request_id)
        page=(f"<!doctype html><html lang=en><head><meta charset=utf-8>"
              f"<meta name=viewport content='width=device-width,initial-scale=1'>"
              f"<title>Semantic record {safe_id}</title><style>{_PANEL_CSS}</style></head><body><main>"
              f"<h1>Full semantic record</h1>"
              f"<p class=muted>Request <code>{safe_id}</code>. This page is a complete sanitized record; "
              f"decisions stay on the <a href='/'>main panel</a>.</p>{fragment}</main></body></html>")
        return self._bounded_html(page,self.DETAIL_MAX_BYTES,"record detail")

    def _decision_card(self, item: Mapping[str,Any], *, csrf: str, now: int, observations=None) -> str:
        """Render one pending decision from the bounded, allowlisted projection only."""
        card=build_decision_card(
            item,catalog=self.catalog,now=now,
            delivery=self.control.ledger.notifications_for_request(str(item.get("request_id","")),
                                                                   limit=MAX_NOTICES+1),
        )
        dry_run=item.get("auto_approval")
        explanation=""
        if isinstance(dry_run,Mapping) and dry_run.get("matched") is False:
            reason=presentation_safe_text(dry_run.get("reason"),limit=300) or "reason withheld"
            explanation=(f"<p class=muted><b>Auto-approval did not apply</b> - {html.escape(reason)}</p>")
        return (f"<article class='decision {html.escape(card['urgency'])}'>{render_decision_card_html(card)}{explanation}"
                f"{self._decision_controls(item,csrf=csrf,card=card)}{self._request_review(item)}"
                f"{self._record_details(item,observations)}</article>")

    def _wired_auto_approval(self):
        """The auto-approval policy actually wired into the backend, never a separate copy."""
        return getattr(self.control.backend, "auto_approval", None)

    def _wired_execution_enabled(self) -> bool:
        """The live execution flag of the effective wired backend path."""
        return getattr(self.control.backend, "execution_enabled", False) is True

    def _rule_state(self, rule: Mapping[str,Any], *, now: int, controls: Mapping[str,Any]) -> str:
        if str(rule["rule_id"]) in (controls.get("disabled_auto_rules") or []): return "Disabled"
        if int(rule["expires_at"])<=now: return "Expired"
        if int(rule["review_by"])<=now: return "Review overdue"
        return "Enabled"

    def _rule_scope(self, rule: Mapping[str,Any]) -> str:
        if rule["action_class"]=="global_simulation":
            return "Standing: every catalogued non-prohibited action, automatic except communications and spending, simulation only"
        parts=[f"class {rule['action_class']}",", ".join(rule["actions"]),f"repo {rule['repository']}",", ".join(rule["refs"])]
        if rule["environments"]: parts.append("environments "+", ".join(rule["environments"]))
        if rule["targets"]: parts.append("targets "+", ".join(rule["targets"]))
        parts.append("requesters "+", ".join(rule["requesters"]))
        parts.append("nodes "+", ".join(rule["nodes"]))
        return " | ".join(parts)

    _HUMAN_GATE_DESCRIPTIONS = {
        "human_communication": "communication, sending or disclosure to a person or external recipient",
        "human_spending": "spending, transferring, purchasing or committing money",
    }

    def _auto_approval_section(self, csrf: str, *, now: int, controls: Mapping[str,Any]) -> str:
        policy=self._wired_auto_approval()
        if policy is None:
            return ("<section aria-labelledby=rules-heading><h2 id=rules-heading>Auto-approval rules</h2>"
                    "<p class=muted>No auto-approval policy is configured; every gated request asks a human.</p></section>")
        execution_enabled=self._wired_execution_enabled()
        paused=controls.get("auto_approval_paused") is True
        disabled=list(controls.get("disabled_auto_rules") or [])
        rules=[rule for rule in (policy.global_simulation_rule,) if rule is not None]+list(policy.rules)
        rows=""
        for rule in rules:
            rule_id=str(rule["rule_id"]); state=self._rule_state(rule,now=now,controls=controls)
            remaining=[item for item in disabled if item!=rule_id]
            toggle_value=", ".join(remaining if state=="Disabled" else sorted(set(disabled)|{rule_id}))
            toggle_label="Enable" if state=="Disabled" else "Disable"
            toggle=(f"<form method=post action='/admin/controls'>"
                    f"{self._hidden({'csrf_token':csrf,'key':'disabled_auto_rules','value':toggle_value})}"
                    f"<button{'' if state=='Disabled' else ' class=danger'} type=submit>{toggle_label}</button></form>")
            rows+=(f"<tr><td><code>{html.escape(rule_id)}</code></td><td>version {int(rule['version'])}</td>"
                   f"<td>{html.escape(self._rule_scope(rule))}</td><td><b>{html.escape(state)}</b></td>"
                   f"<td>Next review {html.escape(_utc(rule['review_by']))}<br>Expires {html.escape(_utc(rule['expires_at']))}</td>"
                   f"<td>{toggle}</td></tr>")
        exclusions="; ".join(
            f"{self._HUMAN_GATE_DESCRIPTIONS[name]} (<code>{html.escape(name)}</code>)" for name in HUMAN_GATE_CLASSES)
        stop=("<b>execution_enabled=true</b>, so the standing simulation-only rule does not apply and every request asks a human"
              if execution_enabled else
              "<b>execution_enabled=false</b> is a separate hard stop, so nothing is executed")
        pause=(f"<form method=post action='/admin/controls'>{self._hidden({'csrf_token':csrf,'key':'auto_approval_paused','value':'false' if paused else 'true'})}"
               f"<button{'' if paused else ' class=danger'} type=submit>{'Resume auto-approval' if paused else 'Pause auto-approval'}</button></form>")
        banner=(f"<p class=banner><b>Automatic except communications and spending</b> - every catalogued non-prohibited "
                f"action is auto-approved, simulation only. Always asks a human: {exclusions}. Prohibited catalogue "
                f"entries are not requestable. {stop}.</p>"
                if policy.global_simulation_rule is not None else
                f"<p class=banner><b>Scoped auto-approval only</b> - simulation only; {stop}.</p>")
        state_line="<p class=warn>Auto-approval is paused by a human; every request asks a human.</p>" if paused else "<p class=muted>Auto-approval is active for the declared scope below.</p>"
        return ("<section aria-labelledby=rules-heading><h2 id=rules-heading>Auto-approval rules</h2>"
                f"{banner}{state_line}<div class=actions>{pause}</div>"
                "<table><thead><tr><th scope=col>Rule</th><th scope=col>Version</th><th scope=col>Declared scope</th>"
                "<th scope=col>State</th><th scope=col>Review</th><th scope=col>Human control</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
                f"<p><b>Always asks a human:</b> {html.escape(', '.join(HUMAN_GATE_CLASSES))}</p>"
                "<p class=muted>Rules are checked-in and host-owned. No agent-callable surface can create, edit, "
                "enable, disable or pause them.</p></section>")

    def _feed_section(self, feed: str, *, audit_events, observations) -> str:
        lanes=partition_audit_events(audit_events)
        telemetry=collapse_observations(observations)
        counts={**{lane:len(rows) for lane,rows in lanes.items()},"telemetry":len(telemetry)}
        nav="".join(
            (f"<b class=chip>{html.escape(self.FEED_LABELS[name])} ({counts.get(name,0)})</b>" if name==feed
             else f"<a href='/?feed={name}'>{html.escape(self.FEED_LABELS[name])} ({counts.get(name,0)})</a>")
            for name in self.FEEDS)
        if feed=="telemetry":
            head="<tr><th scope=col>Outcome</th><th scope=col>Source</th><th scope=col>Operation</th><th scope=col>Events</th><th scope=col>Seen</th></tr>"
            body="".join(
                f"<tr><td>{html.escape(row['label'])}</td><td>{html.escape(row['source'])}</td>"
                f"<td><code>{html.escape(row['operation'])}</code></td>"
                f"<td><code>{html.escape(', '.join(row['event_ids']))}</code> · occurrences {int(row['occurrences'])}</td>"
                f"<td>{html.escape(_utc(row['last_seen_at']))}</td></tr>" for row in reversed(telemetry)) \
                or "<tr><td colspan=5>No execution telemetry.</td></tr>"
        else:
            head="<tr><th scope=col>#</th><th scope=col>What happened</th><th scope=col>Source</th><th scope=col>Request</th><th scope=col>Time</th></tr>"
            body="".join(
                f"<tr><td>{int(row['seq'])}</td><td>{html.escape(row['label'])}</td><td>{html.escape(row['source'])}</td>"
                f"<td><code>{html.escape(row['request_id'] or '')}</code></td><td>{html.escape(_utc(row['at']))}</td></tr>"
                for row in reversed(lanes[feed])) or f"<tr><td colspan=5>No {html.escape(self.FEED_LABELS[feed].casefold())} rows.</td></tr>"
        return ("<section aria-labelledby=feed-heading><h2 id=feed-heading>Activity feeds</h2>"
                f"<nav class=feeds aria-label='Activity feed filters'>{nav}</nav>"
                "<p class=muted>Ordinary tool failures, timeouts, interrupts and cancellations are not Semantic Gate "
                "decisions; they appear only as execution telemetry.</p>"
                f"<table><thead>{head}</thead><tbody>{body}</tbody></table></section>")

    def _control_forms(self, csrf: str) -> str:
        controls=self.control.ledger.controls()
        def switch(value: bool, label: str, css: str) -> str:
            return (f"<form method=post action='/admin/controls'>{self._hidden({'csrf_token':csrf,'key':'pause_all','value':'true' if value else 'false'})}"
                    f"<button{css} type=submit>{html.escape(label)}</button></form>")
        def listing(key: str, label: str, field: str) -> str:
            current=", ".join(controls.get(key) or [])
            return (f"<form method=post action='/admin/controls'>{self._hidden({'csrf_token':csrf,'key':key})}"
                    f"<label for={field}>{html.escape(label)}</label>"
                    f"<input id={field} name=value type=text value='{html.escape(current,quote=True)}' autocapitalize=none spellcheck=false>"
                    f"<button type=submit>Save</button></form>")
        state=(f"<dl class=facts><dt>All proposals paused</dt><dd>{'yes' if controls.get('pause_all') else 'no'}</dd>"
               f"<dt>Paused domains</dt><dd>{html.escape(', '.join(controls.get('paused_domains') or []) or 'none')}</dd>"
               f"<dt>Revoked principals</dt><dd>{html.escape(', '.join(controls.get('revoked_principals') or []) or 'none')}</dd></dl>")
        return (state+f"<div class=actions>{switch(True,'Pause all',' class=danger')}{switch(False,'Resume proposals','')}</div>"
                +listing("paused_domains","Paused domains (comma separated; empty clears)","paused-domains")
                +listing("revoked_principals","Revoked principals (comma separated; empty clears)","revoked-principals"))

    @staticmethod
    def _control_form_value(key: str, raw: str) -> Any:
        """Translate one no-JavaScript control form field into the exact typed control value."""
        if key in {"pause_all","auto_approval_paused"}:
            if raw not in {"true","false"}: raise GateControlError(f"{key} must be true or false")
            return raw=="true"
        if key not in {"paused_domains","revoked_principals","disabled_auto_rules"}: raise GateControlError("unknown control key")
        items=[item.strip() for item in raw.split(",") if item.strip()]
        if len(items)>32 or any(len(item)>128 for item in items): raise GateControlError("control list is too large")
        return items

    @staticmethod
    def _page_param(query: Mapping[str,Any], name: str) -> int:
        raw=(query.get(name) or ["1"])[0]
        if not re.fullmatch(r"[1-9][0-9]{0,5}",raw): raise GateControlError(f"{name} must be a positive integer")
        return int(raw)

    @staticmethod
    def _pager(label: str, param: str, page: int, total: int, size: int, base: str) -> str:
        """Stable next/previous controls; page numbers are validated positive integers."""
        pages=max(1,-(-total//size))
        previous=f" <a href='{base}&{param}={page-1}'>Previous page</a>" if page>1 else ""
        following=f" <a href='{base}&{param}={page+1}'>Next page</a>" if page<pages else ""
        return (f"<nav class=feeds aria-label='{html.escape(label)} pages'>"
                f"<span class=muted>Page {page} of {pages} ({total} total)</span>{previous}{following}</nav>")

    @staticmethod
    def _bounded_html(document: str, max_bytes: int, surface: str) -> Response:
        """Fail closed before responding: oversized panel/detail output is withheld."""
        encoded=document.encode()
        if len(encoded)>max_bytes:
            marker=html.escape(f"[redacted: {surface} exceeds {max_bytes} serialized bytes]")
            fallback=(f"<!doctype html><html lang=en><head><meta charset=utf-8>"
                      f"<meta name=viewport content='width=device-width,initial-scale=1'>"
                      f"<title>Semantic Gate</title><style>{_PANEL_CSS}</style></head><body><main>"
                      f"<h1>Content withheld</h1><p class=warn>{marker}</p>"
                      f"<p><a href='/'>Return to the main panel</a></p></main></body></html>")
            return Response(200,{"Content-Type":"text/html;charset=UTF-8","Cache-Control":"no-store"},fallback.encode())
        return Response(200,{"Content-Type":"text/html;charset=UTF-8","Cache-Control":"no-store"},encoded)

    def _panel(self, session: str, feed: str = "decisions", state: str = "all", *, page: int = 1, pending_page: int = 1) -> Response:
        now=int(self.clock()); csrf=self._csrf(session); controls=self.control.ledger.controls()
        counts=self.control.ledger.request_state_counts()
        pending_total=counts.get("waiting_for_approval",0)
        state_counts={name:counts.get(name,0) for name in self.HISTORY_STATES if name!="all"}
        state_counts["all"]=sum(count for name,count in counts.items() if name!="waiting_for_approval")
        pending=self.control.list_requests(principal=self.admin_principal_id,admin=True,state="waiting_for_approval",
                                           limit=self.PENDING_PAGE_SIZE,offset=(pending_page-1)*self.PENDING_PAGE_SIZE)
        history_filter={"exclude_state":"waiting_for_approval"} if state=="all" else {"state":state}
        completed=self.control.list_requests(principal=self.admin_principal_id,admin=True,
                                             limit=self.HISTORY_PAGE_SIZE,offset=(page-1)*self.HISTORY_PAGE_SIZE,
                                             **history_filter)
        completed_total=state_counts[state]
        observations=self.control.ledger.recent_observations(limit=200)
        base=f"/?feed={feed}&state={state}"
        pending_pager=(self._pager("Pending decisions","pending_page",pending_page,pending_total,
                                   self.PENDING_PAGE_SIZE,f"{base}&page={page}")
                       if pending_total>self.PENDING_PAGE_SIZE or pending_page>1 else "")
        history_pager=self._pager("Completed history","page",page,completed_total,
                                  self.HISTORY_PAGE_SIZE,f"{base}&pending_page={pending_page}")
        state_nav="".join(
            (f"<b class=chip>{name} ({state_counts[name]})</b>" if name==state
             else f"<a href='/?state={name}'>{name} ({state_counts[name]})</a>")
            for name in self.HISTORY_STATES)
        status=self.status_provider()
        relay=status.get("relay",{}) if isinstance(status,Mapping) else {}
        outbox=status.get("notification_outbox",{}) if isinstance(status,Mapping) else {}
        relay_error=relay.get("last_error")
        relay_error=redaction_fingerprint(relay_error,"provider error content") if isinstance(relay_error,str) and relay_error else "none"
        delivery_banner=(f"<p><b>Provider status: {html.escape(str(relay.get('status','not configured')))}</b> · "
                         f"{int(outbox.get('pending',0))} pending · {int(outbox.get('unknown',0))} unknown</p>"
                         f"<p class=muted>Last success: {html.escape(_utc(relay.get('last_success_at')))} · "
                         f"Last error: {html.escape(relay_error)}</p>")
        execution_enabled=self._wired_execution_enabled()
        headline=("Execution is enabled by the loaded policy; simulation-only gates still simulate."
                  if execution_enabled else "Execution is globally disabled; decisions simulate only.")
        execution_banner=("<p class=banner>Execution is enabled by the loaded policy: <b>execution_enabled=true</b>. "
                          "Human approval and a host execution authority are still required for any live effect.</p>"
                          if execution_enabled else
                          "<p class=banner>Execution is globally disabled: <b>execution_enabled=false</b>, simulation only.</p>")
        cards="".join(self._decision_card(item,csrf=csrf,now=now,observations=observations) for item in pending) or "<p class=muted>No decision is waiting.</p>"
        history="".join(
            f"<tr><td><code>{html.escape(str(item.get('request_id','')))}</code></td><td>{html.escape(str(item.get('action','')))}</td>"
            f"<td>{html.escape(str(item.get('requester','')))}</td><td>{html.escape(str(item.get('effective_control','policy')))}</td>"
            f"<td>{html.escape(str(item.get('state','')))}</td><td>{html.escape(_utc(item.get('updated_at') or item.get('created_at')))}</td>"
            f"<td>{self._record_details(item,observations)}</td></tr>"
            for item in completed) or "<tr><td colspan=7>No completed decisions yet.</td></tr>"
        action_rows="".join(f"<tr><td><code>{html.escape(action)}</code></td><td>{html.escape(str(value.get('risk','')))}</td><td>{html.escape(str(value.get('effect','')))}</td><td>{html.escape(str(value.get('summary','')))}</td></tr>" for action,value in sorted(self.catalog.get("actions",{}).items()))
        cred_rows="".join(f"<tr><td>{html.escape(item['credential_id'])}</td><td>{html.escape(item['adapter'])}</td><td>{html.escape(item['status'])}</td></tr>" for item in self.credentials.public_inventory())
        audit_events=self.control.ledger.audit_events(limit=200)
        audit_rows="".join(f"<tr><td>{event['seq']}</td><td>{html.escape(str(event['event']))}</td><td>{html.escape(str(event['actor']))}</td><td><code>{html.escape(str(event.get('request_id') or ''))}</code></td><td>{html.escape(_utc(event['at']))}</td></tr>" for event in audit_events)
        document=(f"<!doctype html><html lang=en><head><meta charset=utf-8>"
              f"<meta name=viewport content='width=device-width,initial-scale=1'>"
              f"<meta http-equiv=refresh content=20>"
              f"<title>Semantic Gate decisions</title><style>{_PANEL_CSS}</style></head><body>"
              f"<a class=skip href='#pending'>Skip to pending decisions</a><main>"
              f"<h1>Semantic Gate</h1><p class=muted>{headline}</p>"
              f"<section aria-labelledby=delivery-heading><h2 id=delivery-heading>Coordinator health</h2>"
              f"{execution_banner}"
              f"{delivery_banner}</section>"
              f"<section id=pending aria-labelledby=pending-heading><h2 id=pending-heading>Pending decisions ({pending_total})</h2>{pending_pager}{cards}</section>"
              f"{self._feed_section(feed,audit_events=audit_events,observations=observations)}"
              f"{self._auto_approval_section(csrf,now=now,controls=controls)}"
              f"<section aria-labelledby=history-heading><h2 id=history-heading>Completed history</h2>"
              f"<nav class=feeds aria-label='History state filters'>{state_nav}</nav>"
              f"{history_pager}"
              f"<table><caption class=muted>Decided requests are terminal and are never revived.</caption><thead><tr>"
              f"<th scope=col>Request</th><th scope=col>Action</th><th scope=col>Requester</th>"
              f"<th scope=col>Effective control</th><th scope=col>State</th><th scope=col>Updated</th>"
              f"<th scope=col>Full record</th></tr></thead>"
              f"<tbody>{history}</tbody></table></section>"
              f"<section aria-labelledby=controls-heading><h2 id=controls-heading>Emergency controls</h2>{self._control_forms(csrf)}</section>"
              f"<section aria-labelledby=reference-heading><h2 id=reference-heading>Reference</h2>"
              f"<details><summary>Action catalogue</summary><table><thead><tr><th scope=col>Action</th><th scope=col>Risk</th>"
              f"<th scope=col>Effect</th><th scope=col>Summary</th></tr></thead><tbody>{action_rows}</tbody></table></details>"
              f"<details><summary>Credential bindings</summary><table><thead><tr><th scope=col>Credential</th>"
              f"<th scope=col>Adapter</th><th scope=col>Status</th></tr></thead><tbody>{cred_rows}</tbody></table></details>"
              f"<details><summary>Full audit ledger</summary><table><caption class=muted>Audit rows are append-only.</caption><thead><tr><th scope=col>#</th><th scope=col>Event</th>"
              f"<th scope=col>Actor</th><th scope=col>Request</th><th scope=col>Time</th></tr></thead>"
              f"<tbody>{audit_rows}</tbody></table></details></section></main></body></html>")
        return self._bounded_html(document,self.PANEL_MAX_BYTES,"panel")

    @staticmethod
    def _login_page() -> Response:
        page=("<!doctype html><html lang=en><head><meta charset=utf-8>"
              "<meta name=viewport content='width=device-width,initial-scale=1'><title>Semantic Gate login</title>"
              "<style>{css}</style></head><body><main><form method=post action=/login><h1>Semantic Gate</h1>"
              "<label for=username>Username</label>"
              "<input id=username name=username type=text autocomplete=username autocapitalize=none spellcheck=false required>"
              "<label for=password>Password</label>"
              "<input id=password name=password type=password autocomplete=current-password required autofocus>"
              "<button type=submit>Sign in</button></form></main></body></html>").format(css=_LOGIN_CSS)
        return Response(200,{"Content-Type":"text/html;charset=UTF-8","Cache-Control":"no-store"},page.encode())

    def _host_context(self, principal: Principal, surface: str) -> dict:
        context = {"surface": surface, "authenticated_principal": principal.principal_id}
        node = self.principal_contexts.get(principal.principal_id, {}).get("node")
        if node is not None:
            if not isinstance(node, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", node):
                raise GateControlError("principal node binding is invalid")
            context["node"] = node
        return context

    def _mcp(self, principal: Principal, message: dict) -> Response:
        request_id=message.get("id"); method=message.get("method"); params=message.get("params",{})
        try:
            if message.get("jsonrpc")!="2.0" or not isinstance(method,str) or not isinstance(params,dict): raise GateControlError("invalid request")
            if method=="initialize": result={"protocolVersion":"2025-03-26","capabilities":{"tools":{"listChanged":False}},"serverInfo":{"name":"semantic-gate","version":"0.2.0"}}
            elif method=="ping": result={}
            elif method=="tools/list": result={"tools":MCP_TOOLS}
            elif method=="tools/call":
                name=params.get("name"); args=params.get("arguments")
                if not isinstance(args,dict): raise GateControlError("tool arguments must be an object")
                if name=="list_actions": value=self.control.list_actions(principal.principal_id)
                elif name=="explain_action": value=self.control.explain_action(args.get("action"),principal.principal_id)
                elif name=="request_action": value=self.control.request_action(principal=principal.principal_id,payload=args,host_context=self._host_context(principal,"mcp"))
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
            if route=="/health" and method=="GET": return _json(200,{"status":"ok","execution_enabled":self._wired_execution_enabled(),**self.status_provider()})
            if route=="/login" and method=="GET": return self._login_page()
            if route=="/login" and method=="POST":
                is_form=(_header(headers,"Content-Type") or "").split(";",1)[0].strip().casefold()=="application/x-www-form-urlencoded"
                credentials=self._form(body) if is_form else self._decode(body)
                supplied_user=credentials.get("username","") if set(credentials)=={"username","password"} else ""
                supplied_password=credentials.get("password","") if set(credentials)=={"username","password"} else ""
                user_ok=isinstance(supplied_user,str) and hmac.compare_digest(supplied_user,self.admin_principal_id)
                password_ok=isinstance(supplied_password,str) and hmac.compare_digest(supplied_password,self.admin_password)
                if not (user_ok and password_ok): return _json(403,{"error":"invalid credentials"})
                session=self.authority.issue_session(self.admin_principal_id,now=int(self.clock()),ttl_seconds=3600)
                secure="; Secure" if self.secure_cookies else ""
                response_headers={"Set-Cookie":f"sg_session={session}; HttpOnly; SameSite=Strict; Path=/{secure}","X-CSRF-Token":self._csrf(session),"Cache-Control":"no-store"}
                if is_form:
                    response_headers["Location"]="/"
                    return Response(303,response_headers,b"")
                return Response(204,response_headers,b"")
            if route=="/" and method=="GET":
                try: _,session=self._admin(headers)
                except AuthError: return Response(303,{"Location":"/login","Cache-Control":"no-store"},b"")
                query=parse_qs(urlsplit(path).query,keep_blank_values=False,max_num_fields=8)
                unknown=set(query)-self.PANEL_QUERY_PARAMS
                if unknown: raise GateControlError(f"unknown query parameter(s): {sorted(unknown)}")
                if any(len(values)!=1 for values in query.values()): raise GateControlError("duplicate query parameter")
                selected=(query.get("feed") or ["decisions"])[0]
                if selected not in self.FEEDS: raise GateControlError("unknown activity feed")
                state=(query.get("state") or ["all"])[0]
                if state not in self.HISTORY_STATES: raise GateControlError("unknown history state filter")
                page=self._page_param(query,"page"); pending_page=self._page_param(query,"pending_page")
                return self._panel(session,selected,state,page=page,pending_page=pending_page)
            if route=="/mcp" and method=="POST": return self._mcp(self._action_bearer(headers),self._decode(body))
            if route=="/api/v1/actions" and method=="GET":
                p=self._action_bearer(headers); return _json(200,self.control.list_actions(p.principal_id))
            if route=="/api/v1/audit-observations" and method=="POST":
                p=self._bearer(headers); return _json(200,self.control.observe(principal=p.principal_id,payload=self._decode(body)))
            if route=="/api/v1/requests" and method=="POST":
                p=self._action_bearer(headers); return _json(201,self.control.request_action(principal=p.principal_id,payload=self._decode(body),host_context=self._host_context(p,"http")))
            if route=="/api/v1/requests" and method=="GET":
                p=self._action_bearer(headers); return _json(200,self.control.list_requests(principal=p.principal_id))
            if route.startswith("/api/v1/requests/"):
                p=self._action_bearer(headers); parts=route.strip("/").split("/")
                if len(parts)==4 and method=="GET":
                    return _json(200,self.control.get_request(parts[3],principal=p.principal_id))
                if len(parts)==5 and parts[4]=="cancel" and method=="POST":
                    return _json(200,self.control.cancel(parts[3],principal=p.principal_id))
                return _json(404,{"error":"not found"})
            if route.startswith("/admin/requests/") and method=="GET":
                parts=route.strip("/").split("/")
                if len(parts)!=3: return _json(404,{"error":"not found"})
                try: self._admin(headers)
                except AuthError: return Response(303,{"Location":"/login","Cache-Control":"no-store"},b"")
                return self._request_detail(parts[2])
            if route.startswith("/admin/requests/") and method=="POST":
                is_form=(_header(headers,"Content-Type") or "").split(";",1)[0].strip().casefold()=="application/x-www-form-urlencoded"
                submitted=self._form(body) if is_form else self._decode(body)
                csrf_token=submitted.pop("csrf_token",None) if is_form else None
                p=self._require_mutation(headers,csrf_token=csrf_token); parts=route.strip("/").split("/")
                if len(parts)!=4: return _json(404,{"error":"not found"})
                request_id,op=parts[2],parts[3]
                challenge=submitted
                if is_form:
                    if set(challenge)!={"request_id","request_hash","approval_gate_id","expires_at"}: raise GateControlError("decision form is invalid")
                    try: challenge["expires_at"]=int(challenge["expires_at"])
                    except ValueError as error: raise GateControlError("decision deadline is invalid") from error
                if op=="approve": value=self.control.approve(request_id,actor=p.principal_id,actor_role=p.role,challenge=challenge)
                elif op=="deny": value=self.control.deny(request_id,actor=p.principal_id,actor_role=p.role,challenge=challenge)
                else: return _json(404,{"error":"not found"})
                return Response(303,{"Location":"/","Cache-Control":"no-store"},b"") if is_form else _json(200,value)
            if route=="/admin/controls" and method=="POST":
                is_form=(_header(headers,"Content-Type") or "").split(";",1)[0].strip().casefold()=="application/x-www-form-urlencoded"
                submitted=self._form(body) if is_form else self._decode(body)
                csrf_token=submitted.pop("csrf_token",None) if is_form else None
                p=self._require_mutation(headers,csrf_token=csrf_token)
                if set(submitted)!={"key","value"}: raise GateControlError("control body must contain exactly key and value")
                key,value=submitted["key"],submitted["value"]
                if is_form: value=self._control_form_value(key,value)
                if key in {"pause_all","auto_approval_paused"} and type(value) is not bool: raise GateControlError(f"{key} must be boolean")
                if key in {"paused_domains","revoked_principals","disabled_auto_rules"} and (not isinstance(value,list) or any(not isinstance(item,str) or not item for item in value)): raise GateControlError("control list is invalid")
                updated=self.control.set_control(key,value,actor=p.principal_id)
                return Response(303,{"Location":"/","Cache-Control":"no-store"},b"") if is_form else _json(200,updated)
            return _json(404,{"error":"not found"})
        except GateDecisionConflict as error: return _json(409,{"error":str(error)})
        except PermissionError as error: return _json(403,{"error":str(error)})
        except AuthError as error: return _json(401 if route.startswith(("/api/","/mcp")) else 403,{"error":str(error)})
        except (GateControlError,KeyError,ValueError) as error: return _json(400,{"error":str(error)})
