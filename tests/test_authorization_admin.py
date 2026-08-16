#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import sqlite3
import unittest
from contextlib import redirect_stderr,redirect_stdout
from io import StringIO
from pathlib import Path

from semantic_gate.authorization import HMACAuthorizationAuthority,SQLiteAuthorizationStore
from semantic_gate.authorization_admin import main
from tests.test_authorization import claims


class AuthorizationAdminTests(unittest.TestCase):
    def test_missing_or_unrelated_database_is_rejected_without_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing=Path(tmp)/"mistyped.sqlite3"
            with redirect_stderr(StringIO()),self.assertRaises(SystemExit): main(["list","--database",str(missing)])
            self.assertFalse(missing.exists())
            unrelated=Path(tmp)/"unrelated.sqlite3"; sqlite3.connect(unrelated).close()
            with redirect_stderr(StringIO()),self.assertRaises(SystemExit): main(["list","--database",str(unrelated)])
            with sqlite3.connect(unrelated) as db: self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='authorizations'").fetchone())

    def test_list_and_bulk_revoke_are_metadata_only_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"gate.sqlite3"; store=SQLiteAuthorizationStore(path); authority=HMACAuthorizationAuthority(b"a"*32,issuer="gate-host")
            store.record_issued(authority.issue(claims(authorization_id="auth_one"))); store.record_issued(authority.issue(claims(authorization_id="auth_two"))); store.close()
            output=StringIO()
            with redirect_stdout(output): self.assertEqual(0,main(["list","--database",str(path),"--state","issued"]))
            listed=json.loads(output.getvalue()); self.assertEqual(["auth_one","auth_two"],[item["authorization_id"] for item in listed["authorizations"]]); self.assertNotIn("token",output.getvalue()); self.assertNotIn("signature",output.getvalue())
            output=StringIO()
            with redirect_stdout(output): self.assertEqual(0,main(["revoke-issued","--database",str(path),"--actor","rollback-operator"]))
            self.assertEqual(2,json.loads(output.getvalue())["revoked"])
            output=StringIO()
            with redirect_stdout(output): self.assertEqual(0,main(["revoke-issued","--database",str(path),"--actor","rollback-operator"]))
            self.assertEqual(0,json.loads(output.getvalue())["revoked"])
            check=SQLiteAuthorizationStore(path); self.assertEqual({"cancelled"},{item["state"] for item in check.list_metadata()}); check.close()

    def test_explicit_recovery_and_reconciliation_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"gate.sqlite3"; receipt=Path(tmp)/"receipt.json"; receipt.write_text('{"order_id":"one"}')
            store=SQLiteAuthorizationStore(path); authority=HMACAuthorizationAuthority(b"a"*32,issuer="gate-host"); store.record_issued(authority.issue(claims(authorization_id="auth_recover"))); store.begin_consumption("auth_recover",consumer="example-agent",now=110); store.close()
            with redirect_stdout(StringIO()): self.assertEqual(0,main(["recover-interrupted","--database",str(path),"--authorization-id","auth_recover","--actor","operator"]))
            with redirect_stdout(StringIO()): self.assertEqual(0,main(["reconcile","--database",str(path),"--authorization-id","auth_recover","--actor","operator","--outcome","executed","--receipt-file",str(receipt)]))
            check=SQLiteAuthorizationStore(path); self.assertEqual("executed",check.get("auth_recover")["state"]); check.close()


if __name__=="__main__": unittest.main()
