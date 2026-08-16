#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from semantic_gate.credentials import CredentialRegistry


class CredentialRegistryTests(unittest.TestCase):
    def test_public_inventory_never_contains_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.local.json"
            path.write_text(json.dumps({"credentials": {
                "home-assistant": {"kind":"bearer","adapter":"homeassistant","value":"super-secret-token"},
                "google-calendar": {"kind":"oauth","adapter":"calendar","disabled":True,"value":"refresh-secret"},
            }}))
            registry = CredentialRegistry(path)
            inventory = registry.public_inventory()
            rendered = json.dumps(inventory)
            self.assertNotIn("super-secret", rendered)
            self.assertNotIn("refresh-secret", rendered)
            self.assertEqual("available", inventory[0]["status"])
            self.assertEqual("disabled", inventory[1]["status"])
            self.assertEqual("super-secret-token", registry.require("home-assistant"))
            with self.assertRaises(KeyError):
                registry.require("google-calendar")


if __name__ == "__main__":
    unittest.main()
