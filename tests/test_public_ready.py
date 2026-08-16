#!/usr/bin/env python3
from __future__ import annotations

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
            if not path.is_file() or path.suffix.lower() not in {".md", ".json", ".yml", ".yaml"}:
                continue
            text = path.read_text(errors="replace")
            lowered = text.casefold()
            checked.append(path)
            for value in forbidden_fragments:
                self.assertNotIn(value.casefold(), lowered, f"live binding {value!r} in {path.relative_to(ROOT)}")
            for field in credential_fields:
                self.assertNotIn(f'"{field}"', lowered, f"credential field {field!r} in {path.relative_to(ROOT)}")
        self.assertTrue(checked)

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

    def test_no_tracked_secrets_or_environment_files(self):
        completed = subprocess.run(["git","ls-files"],cwd=ROOT,text=True,capture_output=True,check=True)
        suspicious = [line for line in completed.stdout.splitlines() if "secret" in line.casefold() or line.endswith(".env")]
        self.assertEqual([],suspicious)


if __name__ == "__main__":
    unittest.main()
