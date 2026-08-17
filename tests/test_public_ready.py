#!/usr/bin/env python3
from __future__ import annotations

import json
import ast
import hashlib
import re
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from semantic_gate.engine import load_policy  # noqa: E402


class PublicReadinessTests(unittest.TestCase):
    def test_examples_are_portable_and_contain_no_live_environment_bindings(self):
        checked = []
        forbidden_fragments = ("/Users/", "/home/", "http://", "https://", ".local", ".internal")
        credential_fields = ("api_key", "password", "private_key", "access_token", "secret")
        for path in (ROOT / "examples").rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".md", ".json", ".yml", ".yaml", ".py"}:
                continue
            text = path.read_text(errors="replace")
            lowered = text.casefold()
            checked.append(path)
            for value in forbidden_fragments:
                self.assertNotIn(value.casefold(), lowered, f"live binding {value!r} in {path.relative_to(ROOT)}")
            for field in credential_fields:
                self.assertNotIn(f'"{field}"', lowered, f"credential field {field!r} in {path.relative_to(ROOT)}")
        self.assertTrue(checked)

    def test_integration_guide_and_examples_cover_extension_options(self):
        guide=(ROOT/"docs/INTEGRATION_GUIDE.md").read_text()
        readme=(ROOT/"README.md").read_text()
        required=(
            "Direct Python SDK","HTTP API","MCP","Content-free observer",
            "RecipePlugin","NodeBroker","minimum_control","Policy decides",
            "Approval issues permission; it does not execute","Private deployment boundary",
        )
        for value in required: self.assertIn(value,guide)
        self.assertIn("docs/INTEGRATION_GUIDE.md",readme)
        for phrase in ("What this helps with","existing MCP","multi-step","bypass"):
            self.assertIn(phrase,readme)
        examples=ROOT/"examples/integrations"
        expected={"sdk_request.py","http_request.py","observer.py","recipe_plugin.py","mcp-request.json","git-actions.json","buzz_approval_flow.py","existing_mcp_adapter.py","mcp_host_smoke.py","multi_step_flow.py","stdio_mcp_client.py","example_downstream_mcp.py","README.md"}
        self.assertTrue(expected <= {path.name for path in examples.iterdir()})
        self.assertIn("Git fetch/pull/push example",guide)
        for path in examples.glob("*.py"):
            subprocess.run([sys.executable,"-m","py_compile",str(path)],check=True,cwd=ROOT)
        for name in ("buzz_approval_flow.py","existing_mcp_adapter.py","multi_step_flow.py"):
            completed=subprocess.run([sys.executable,str(examples/name)],cwd=ROOT,text=True,capture_output=True,check=True,env={"PYTHONPATH":str(ROOT/"src")})
            outcome=json.loads(completed.stdout)
            self.assertTrue(outcome["ok"],name)
            self.assertFalse(outcome["execution_enabled"],name)
        mcp_outcome=json.loads(subprocess.run([sys.executable,str(examples/"existing_mcp_adapter.py")],cwd=ROOT,text=True,capture_output=True,check=True,env={"PYTHONPATH":str(ROOT/"src")}).stdout)
        self.assertTrue(mcp_outcome["real_stdio_jsonrpc"])
        self.assertEqual(2,mcp_outcome["downstream_processes"])
        buzz_outcome=json.loads(subprocess.run([sys.executable,str(examples/"buzz_approval_flow.py")],cwd=ROOT,text=True,capture_output=True,check=True,env={"PYTHONPATH":str(ROOT/"src")}).stdout)
        self.assertTrue(buzz_outcome["verified_transport_boundary"])
        self.assertFalse(buzz_outcome["buzz_signature_verification_implemented"])
        makefile=(ROOT/"Makefile").read_text()
        for target in ("example-buzz:","example-mcp:","example-mcp-host:","example-mcp-enforcing-mock:","example-multistep:","examples:"):
            self.assertIn(target,makefile)
        install=(examples/"README.md").read_text()
        for phrase in ("pip install","Before: agent connects directly","After: agent connects only","not a transparent proxy","demo-only","does not automatically wrap","Production migration","/absolute/path/to/semantic-gate/.venv/bin/python"):
            self.assertIn(phrase,install)
        for phrase in ("ExecutionAuthority","mode=\"enforcing\"","execution_enabled=true","simulation_only=false","local mock"):
            self.assertIn(phrase,install)
        enforcing=json.loads(subprocess.run([sys.executable,str(examples/"existing_mcp_adapter.py"),"--enforcing-demo"],cwd=ROOT,text=True,capture_output=True,check=True,env={"PYTHONPATH":str(ROOT/"src")}).stdout)
        self.assertEqual("executed",enforcing["state"])
        self.assertTrue(enforcing["direct_agent_target_denied"])
        self.assertEqual(1,enforcing["effectful_mcp_calls"])

    def test_public_guides_explain_buzz_mcp_assertions_and_agent_owned_multistep_flow(self):
        required={
            "docs/BUZZ_INTEGRATION.md":("End-to-end sequence","Exact bindings","Failure handling","Buzz does not execute"),
            "docs/EXISTING_TOOLS_AND_MCP.md":("Existing MCP servers","read-only precondition","effectful target","remove the raw"),
            "docs/MULTI_STEP_FLOWS.md":("Agent owns the flow","approval issues authorization","Compensation","Unknown outcome"),
            "docs/ASSERTIONS.md":("Semantic Gate asserts","Host must assert","Semantic Gate does not assert"),
        }
        readme=(ROOT/"README.md").read_text()
        for relative,phrases in required.items():
            text=(ROOT/relative).read_text()
            self.assertIn(relative,readme)
            for phrase in phrases: self.assertIn(phrase,text,relative)

    def test_docs_describe_deferred_beta_authorization_semantics(self):
        paths=(ROOT/"README.md",ROOT/"docs/INTEGRATION_GUIDE.md",ROOT/"docs/BUZZ_INTEGRATION.md",ROOT/"docs/MULTI_STEP_FLOWS.md")
        combined="\n".join(path.read_text() for path in paths)
        for false_claim in ("advances synchronously","immediately calls the registered target","no later agent-controlled consumption","Status:** alpha"):
            self.assertNotIn(false_claim,combined)
        guide=(ROOT/"docs/INTEGRATION_GUIDE.md").read_text()
        for truth in ("Approval issues permission; it does not execute","atomically reserves","explicit reconciliation"):
            self.assertIn(truth,guide)
        self.assertNotIn("mark_interrupted_unknown",(ROOT/"src/semantic_gate/httpd.py").read_text())
        self.assertNotIn("expire_unresolved",(ROOT/"src/semantic_gate/httpd.py").read_text())

    def test_beta_release_documents_are_actionable(self):
        required={
            "docs/QUICKSTART.md":("make examples","version 2","authorized"),
            "docs/BETA.md":("Beta acceptance criteria","Unknown outcomes","Compatibility"),
            "docs/MIGRATING_TO_0_3.md":("version 1","version 2","SEMANTIC_GATE_AUTHORIZATION_KEY","Rollback"),
            "docs/ED25519_APPROVALS.md":("semantic-gate[approvals]","public key","semantic-gate-sign-approval"),
            "docs/ADAPTER_HOST.md":("semantic-gate-adapter-check","absolute","pass_environment"),
            "CHANGELOG.md":("0.3.0b1","Deferred authorization"),
        }
        readme=(ROOT/"README.md").read_text()
        for relative,phrases in required.items():
            text=(ROOT/relative).read_text()
            for phrase in phrases: self.assertIn(phrase,text,relative)
            if relative.startswith("docs/"): self.assertIn(relative,readme)
        metadata=(ROOT/"pyproject.toml").read_text(); self.assertIn("Development Status :: 4 - Beta",metadata); self.assertNotIn("Development Status :: 3 - Alpha",metadata)
        broker_examples=("README.md","ARCHITECTURE.md","examples/README.md","examples/integrations/README.md","docs/EXISTING_TOOLS_AND_MCP.md","examples/integrations/existing_mcp_adapter.py")
        def broker_calls(text):
            calls=[]; marker="AuthorizationBroker("; position=0
            while True:
                start=text.find(marker,position)
                if start<0: return calls
                index=start+len(marker); depth=1; quote=None; escaped=False
                while index<len(text) and depth:
                    character=text[index]
                    if quote:
                        if escaped: escaped=False
                        elif character=="\\": escaped=True
                        elif character==quote: quote=None
                    elif character in {"'",'"'}: quote=character
                    elif character=="(": depth+=1
                    elif character==")": depth-=1
                    index+=1
                if depth: return calls
                calls.append(text[start+len(marker):index-1]); position=index
        for relative in broker_examples:
            calls=broker_calls((ROOT/relative).read_text())
            self.assertTrue(calls,relative)
            for call in calls:
                self.assertIn("revocation_checker=",call,relative)
                self.assertIn("expected_policy_hash=engine.policy_hash",call,relative)
        self.assertTrue((ROOT/"examples/integrations/ed25519_approval_flow.py").is_file())

    def test_standalone_implementation_guide_is_complete_and_prominent(self):
        relative="SEMANTIC_GATE_IMPLEMENTATION_GUIDE.md"
        path=ROOT/relative
        self.assertTrue(path.is_file())
        guide=path.read_text()
        self.assertGreater(len(guide),30_000)
        self.assertIn(relative,(ROOT/"README.md").read_text())
        required=(
            "# Semantic Gate: Standalone Implementation Guide",
            "Status: public beta 0.3.0b1",
            "Threat model", "Non-goals", "Trust boundaries",
            "Policy owns the minimum control", "Canonical JSON",
            "Request fingerprint", "Human approval schema",
            "Ed25519 roster", "Authorization claims",
            "Host-only bearer storage", "ID-only consumption",
            "Request state machine", "Authorization state machine",
            "BEGIN IMMEDIATE", "request_idempotency",
            "Unknown outcome", "explicit reconciliation",
            "Declarative MCP adapter", "revocation_checker",
            "expected_policy_hash=engine.policy_hash",
            "HTTP boundary", "MCP boundary", "SDK boundary",
            "simulation_only", '"execution_enabled": false',
            "Bypass removal", "Migration", "Rollback",
            "Acceptance tests", "Beta limitations",
            "not production-ready", "does not control workflow",
        )
        for phrase in required: self.assertIn(phrase,guide,phrase)
        for fence in ("```json","```sql","```python","```sh","```text"):
            self.assertIn(fence,guide)
        self.assertNotIn("See the README",guide)
        self.assertNotIn("consult the repository",guide.casefold())

    def test_standalone_guide_code_fences_are_copyable(self):
        guide=(ROOT/"SEMANTIC_GATE_IMPLEMENTATION_GUIDE.md").read_text()
        blocks=re.findall(r"```(\w+)\n(.*?)```",guide,re.DOTALL)
        counts={}
        for language,body in blocks:
            counts[language]=counts.get(language,0)+1
            if language=="json": json.loads(body)
            elif language=="python": ast.parse(body)
            elif language=="sql":
                database=sqlite3.connect(":memory:")
                try: database.executescript(body)
                finally: database.close()
        for language in ("json","python","sql","sh","text"):
            self.assertGreater(counts.get(language,0),0,language)

    def test_standalone_guide_canonicalization_vectors_match_reference(self):
        guide=(ROOT/"SEMANTIC_GATE_IMPLEMENTATION_GUIDE.md").read_text()
        value={"label":"café","count":1,"active":True}
        engine=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
        signed=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
        self.assertIn(hashlib.sha256(engine).hexdigest(),guide)
        self.assertIn(hashlib.sha256(signed).hexdigest(),guide)
        documents=[]
        for body in re.findall(r"```json\n(.*?)```",guide,re.DOTALL):
            document=json.loads(body)
            if isinstance(document,dict) and document.get("version")==2 and "workflows" in document: documents.append(document)
        self.assertEqual(1,len(documents))
        encoded=json.dumps(documents[0],sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
        self.assertIn(hashlib.sha256(encoded).hexdigest(),guide)


    def test_all_example_workflows_are_valid_and_simulation_only(self):
        workflows = sorted((ROOT / "examples").glob("*/workflow.json"))
        self.assertGreaterEqual(len(workflows), 3)
        for path in workflows:
            with self.subTest(path=path):
                policy = load_policy(path)
                self.assertEqual("simulation_only", policy["mode"])
                self.assertFalse(policy["execution_enabled"])
                self.assertEqual(2,policy["version"])
                self.assertIn("authorization",policy)

    def test_generic_package_contains_no_private_deployment_identifiers(self):
        forbidden = ("he" + "lm.action.", "fau" + "man", "home" + ":8662", "100.99" + ".36.95")
        paths = list((ROOT / "src").rglob("*.py")) + list((ROOT / "tests").rglob("*.py"))
        for path in paths:
            text = path.read_text(errors="replace").casefold()
            for value in forbidden:
                self.assertNotIn(value.casefold(), text, f"private identifier {value!r} in {path.relative_to(ROOT)}")
        self.assertNotIn("value="+"char"+"les",(ROOT/"src/semantic_gate/server.py").read_text().casefold())

    def test_security_policy_has_actionable_reporting_and_supported_versions(self):
        policy=(ROOT/"SECURITY.md").read_text()
        self.assertIn("## Supported versions",policy)
        self.assertIn("../../security/advisories/new",policy)
        self.assertNotIn("Before public release",policy)

    def test_no_tracked_secrets_or_environment_files(self):
        completed = subprocess.run(["git","ls-files"],cwd=ROOT,text=True,capture_output=True,check=True)
        suspicious = [line for line in completed.stdout.splitlines() if "secret" in line.casefold() or line.endswith(".env")]
        self.assertEqual([],suspicious)


if __name__ == "__main__":
    unittest.main()
