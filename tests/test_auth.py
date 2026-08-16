#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from semantic_gate.auth import AuthError, CapabilityAuthority


class CapabilityAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.authority = CapabilityAuthority(bytes.fromhex("11" * 32), {
            "hermes-mac": {"role": "agent", "enabled": True},
            "control-panel": {"role": "admin", "enabled": True},
            "device-audit": {"role": "observer", "enabled": True},
            "revoked-agent": {"role": "agent", "enabled": False},
        })

    def test_token_identity_is_host_derived(self):
        token = self.authority.token_for("hermes-mac")
        principal = self.authority.authenticate_bearer(f"Bearer {token}")
        self.assertEqual("hermes-mac", principal.principal_id)
        self.assertEqual("agent", principal.role)
        observer=self.authority.authenticate_bearer(f"Bearer {self.authority.token_for('device-audit')}")
        self.assertEqual("observer",observer.role)

    def test_unknown_forged_and_revoked_tokens_fail_closed(self):
        for header in (None, "", "Basic nope", "Bearer forged", f"Bearer {self.authority.token_for('revoked-agent')}"):
            with self.subTest(header=header), self.assertRaises(AuthError):
                self.authority.authenticate_bearer(header)

    def test_admin_session_is_separate_expiring_and_tamper_evident(self):
        session = self.authority.issue_session("control-panel", now=100, ttl_seconds=60)
        self.assertEqual("control-panel", self.authority.verify_session(session, now=159).principal_id)
        with self.assertRaises(AuthError):
            self.authority.verify_session(session + "x", now=120)
        with self.assertRaises(AuthError):
            self.authority.verify_session(session, now=160)
        with self.assertRaises(AuthError):
            self.authority.issue_session("hermes-mac", now=100, ttl_seconds=60)


if __name__ == "__main__":
    unittest.main()
