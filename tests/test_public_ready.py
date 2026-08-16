#!/usr/bin/env python3
from __future__ import annotations

import json
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
            "advancement is synchronous","Private deployment boundary",
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
            "docs/MULTI_STEP_FLOWS.md":("Agent owns the flow","advances synchronously","Compensation","Unknown outcome"),
            "docs/ASSERTIONS.md":("Semantic Gate asserts","Host must assert","Semantic Gate does not assert"),
        }
        readme=(ROOT/"README.md").read_text()
        for relative,phrases in required.items():
            text=(ROOT/relative).read_text()
            self.assertIn(relative,readme)
            for phrase in phrases: self.assertIn(phrase,text,relative)

    def test_docs_describe_current_synchronous_post_approval_semantics(self):
        paths=(ROOT/"README.md",ROOT/"docs/INTEGRATION_GUIDE.md",ROOT/"docs/BUZZ_INTEGRATION.md",ROOT/"docs/MULTI_STEP_FLOWS.md")
        combined="\n".join(path.read_text() for path in paths)
        for false_claim in ("simulated/authorized","consume a bounded authorization later","invoke a separate broker","state\"] != \"authorized\""):
            self.assertNotIn(false_claim,combined)
        guide=(ROOT/"docs/INTEGRATION_GUIDE.md").read_text()
        for truth in ("synchronously advances","registered target","does not expose approval ingestion to the agent"):
            self.assertIn(truth,guide)


    def test_all_example_workflows_are_valid_and_simulation_only(self):
        workflows = sorted((ROOT / "examples").glob("*/workflow.json"))
        self.assertGreaterEqual(len(workflows), 3)
        for path in workflows:
            with self.subTest(path=path):
                policy = load_policy(path)
                self.assertEqual("simulation_only", policy["mode"])
                self.assertFalse(policy["execution_enabled"])

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
