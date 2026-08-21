#!/usr/bin/env python3
"""Complete sanitized semantic record: projection unit tests and panel/detail-route tests."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from semantic_gate.auth import CapabilityAuthority
from semantic_gate.autoapproval import AutoApprovalPolicy
from semantic_gate.catalog import build_policy
from semantic_gate.controller import GateControl
from semantic_gate.coordinator import CoreBackend
from semantic_gate.credentials import CredentialRegistry
from semantic_gate.record import (
    MAX_AUDIT,
    MAX_DEPTH,
    MAX_GATES,
    MAX_ITEMS,
    MAX_NOTICES,
    MAX_STRING,
    MAX_TELEMETRY,
    build_semantic_record,
    canonical_record_json,
    enforce_record_bounds,
    render_semantic_record_html,
    sanitize_semantic_value,
)
from semantic_gate.server import SemanticGateApplication
from semantic_gate.storage import Ledger


CATALOG = {"version": 1, "actions": {
    "home.tv.power_off": {
        "domain": "home", "risk": "R2", "effect": "external_write",
        "summary": "Turn off the allowlisted TV", "approval": "separate_confirmation",
        "gate_class": "automatic", "privacy_classes": ["household_presence"],
        "constraints": ["allowlisted devices only"],
        "presentation": {"proposed_effect": "Turn off the allowlisted TV", "reason": "Idle device",
                         "node": "node-example-1", "safe_target_field": "target",
                         "safe_target_values": ["living-room-tv"], "spends": False,
                         "communicates": False, "changes_state": True},
    },
    "communication.send": {
        "domain": "communication", "risk": "R3", "effect": "external_write",
        "summary": "Send a message to a person", "approval": "separate_confirmation",
        "gate_class": "human_communication", "privacy_classes": ["correspondence"],
        "constraints": ["reviewed recipients only"], "sensitive_parameters": ["draft_note"],
    },
}}
PRINCIPALS = {
    "agent": {"role": "agent", "enabled": True, "node": "node-example-1"},
    "agent-two": {"role": "agent", "enabled": True},
    "control": {"role": "admin", "enabled": True},
}


class CountingIterable:
    """Adversarial one-shot iterable that records exactly how many items were consumed."""

    def __init__(self, items):
        self._iterator = iter(items)
        self.consumed = 0

    def __iter__(self):
        return self

    def __next__(self):
        item = next(self._iterator)
        self.consumed += 1
        return item


def snapshot(**overrides) -> dict:
    base = {
        "request_id": "req_" + "a" * 24,
        "request_hash": "b" * 64,
        "action": "home.tv.power_off",
        "parameters": {"summary": "Turn TV off", "target": "living-room-tv", "details": {"room": "lounge"}},
        "context": {"surface": "test"},
        "requester": "agent",
        "idempotency_key": "unit-one",
        "minimum_control": "policy",
        "policy_control": "ask",
        "effective_control": "ask",
        "state": "waiting_for_approval",
        "blocked_by": None,
        "notification_delivered": True,
        "execution_possible": False,
        "created_at": 100,
        "updated_at": 100,
        "trusted_context_hash": "c" * 64,
        "approval_challenge": {"request_id": "req_" + "a" * 24, "request_hash": "b" * 64,
                               "approval_gate_id": "approval", "expires_at": 700},
        "gates": [
            {"id": "schema", "kind": "schema", "status": "passed", "evidence": {"normalized": True}},
            {"id": "notify", "kind": "notify", "status": "passed",
             "evidence": {"delivered": True, "notification_id": "notice_1", "recipient": "human_owner"}},
            {"id": "approval", "kind": "approval", "status": "waiting",
             "evidence": {"level": "human_approve_once", "ttl_seconds": 600, "request_hash": "b" * 64}},
            {"id": "execute", "kind": "execute", "status": "pending", "evidence": None},
        ],
    }
    base.update(overrides)
    return base


class SanitizerTests(unittest.TestCase):
    def test_recursive_redaction_marks_secrets_commands_and_bodies_at_every_depth(self):
        value = {
            "api_token": "tok-secret-123",
            "details": {
                "body": "the raw message body",
                "safe": "kept value",
                "nested": [{"password": "hunter2"}, {"command": "rm -rf /"}, {"prompt": "system prompt text"}],
            },
        }
        clean = sanitize_semantic_value(value)
        encoded = json.dumps(clean)
        for secret in ("tok-secret-123", "the raw message body", "hunter2", "rm -rf /", "system prompt text",
                       "kept value"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, encoded)
        self.assertTrue(clean["api_token"].startswith("[redacted:"))
        self.assertTrue(clean["details"]["body"].startswith("[redacted:"))
        self.assertTrue(clean["details"]["nested"][0]["password"].startswith("[redacted:"))
        self.assertTrue(clean["details"]["nested"][1]["command"].startswith("[redacted:"))
        self.assertTrue(clean["details"]["nested"][2]["prompt"].startswith("[redacted:"))
        # Even unlisted fields fail closed: the value becomes explicit redaction metadata.
        self.assertTrue(clean["details"]["safe"].startswith("[redacted:"))
        self.assertIn("sha256=", clean["details"]["safe"])
        self.assertIn("chars=10", clean["details"]["safe"])

    def test_camelcase_and_synonym_key_spellings_fail_closed(self):
        value = {
            "accessToken": "raw-access-token", "cookieJar": "raw-cookie-jar",
            "systemPrompt": "raw system prompt", "commandLine": "raw command line",
            "bodyText": "raw body text", "file_text": "raw file text",
            "passphrase": "raw passphrase", "SessionCookie": "raw session cookie",
        }
        clean = sanitize_semantic_value(value)
        encoded = json.dumps(clean)
        for key, raw in value.items():
            with self.subTest(key=key):
                self.assertNotIn(raw, encoded)
                self.assertEqual("[redacted: sensitive field name]", clean[key])

    def test_basic_auth_and_high_entropy_values_are_redacted_without_hashes(self):
        value = {"note": "Basic dXNlcjpwYXNzd29yZA==", "generated": "A1b2C3d4E5f6G7h8J9k0L1m2"}
        clean = sanitize_semantic_value(value)
        for field in ("note", "generated"):
            with self.subTest(field=field):
                self.assertIn("secret material", clean[field])
                self.assertNotIn("sha256=", clean[field])
        self.assertNotIn("dXNlcjpwYXNz", json.dumps(clean))

    def test_mapping_keys_are_sanitized_not_just_values(self):
        secret_key = "ghp_" + "A1b2C3d4" * 5
        clean = sanitize_semantic_value({secret_key: True, "</pre><script>alert(1)</script>": 1})
        encoded = json.dumps(clean)
        self.assertNotIn(secret_key, encoded)
        self.assertNotIn("<script", encoded)
        self.assertEqual(2, sum(1 for key in clean if key.startswith("[redacted key:")))

    def test_secret_looking_values_are_redacted_under_benign_keys(self):
        clean = sanitize_semantic_value({"note": "Bearer abcdef123", "pem": "-----BEGIN PRIVATE KEY-----"})
        self.assertTrue(clean["note"].startswith("[redacted:"))
        self.assertTrue(clean["pem"].startswith("[redacted:"))
        self.assertNotIn("abcdef123", json.dumps(clean))

    def test_schema_marked_sensitive_fields_are_redacted(self):
        clean = sanitize_semantic_value({"draft_note": "private data", "other": "fine"},
                                        sensitive_fields=frozenset({"draft_note"}))
        self.assertTrue(clean["draft_note"].startswith("[redacted:"))
        self.assertIn("schema", clean["draft_note"])
        self.assertTrue(clean["other"].startswith("[redacted:"))
        self.assertIn("sha256=", clean["other"])

    def test_schema_marked_presentation_safe_fields_render_bounded(self):
        clean = sanitize_semantic_value({"room_label": "Meeting room 4", "other": "not safe"},
                                        safe_fields=frozenset({"room_label"}))
        self.assertEqual("Meeting room 4", clean["room_label"])
        self.assertTrue(clean["other"].startswith("[redacted:"))
        # Presentation-safe marking never overrides the credential screens.
        screened = sanitize_semantic_value({"room_label": "Bearer abcdef123"},
                                           safe_fields=frozenset({"room_label"}))
        self.assertIn("secret material", screened["room_label"])

    def test_depth_and_size_limits_fail_closed_with_explicit_markers(self):
        deep: dict = {"leaf": "value"}
        for _ in range(MAX_DEPTH + 2):
            deep = {"level": deep}
        clean = sanitize_semantic_value(deep)
        for _ in range(MAX_DEPTH):
            clean = clean["level"]
        self.assertIsInstance(clean, str)
        self.assertIn("[redacted:", clean)
        self.assertIn("depth", clean)

        big_list = sanitize_semantic_value(list(range(MAX_ITEMS + 5)))
        self.assertEqual(MAX_ITEMS + 1, len(big_list))
        self.assertIn("5 additional", big_list[-1])

        big_map = sanitize_semantic_value({f"key{index:03}": index for index in range(MAX_ITEMS + 3)})
        self.assertIn("3 additional", json.dumps(big_map))

        long_string = sanitize_semantic_value("x" * (MAX_STRING + 50))
        self.assertIn("[redacted:", long_string)
        self.assertIn(f"chars={MAX_STRING + 50}", long_string)
        self.assertLess(len(long_string), MAX_STRING)

        long_safe = sanitize_semantic_value({"label": "word " * 100}, safe_fields=frozenset({"label"}))
        self.assertLessEqual(len(long_safe["label"]), MAX_STRING)
        self.assertTrue(long_safe["label"].endswith("..."))

    def test_binary_and_unsupported_values_are_redacted(self):
        clean = sanitize_semantic_value({"blob_data": b"\x00\x01", "weird": object()})
        self.assertIn("[redacted:", str(clean["blob_data"]))
        self.assertIn("[redacted:", str(clean["weird"]))


class SemanticRecordProjectionTests(unittest.TestCase):
    def test_trusted_context_values_never_render_only_the_hash(self):
        request = snapshot()
        request["trusted_context"] = {"internal_fact": "internal-only-fact"}
        request["context"] = {"trusted_context": {"leaked": "internal-only-fact"}}
        record = build_semantic_record(request, catalog=CATALOG)
        encoded = canonical_record_json(record)
        self.assertNotIn("internal-only-fact", encoded)
        self.assertNotIn("internal_fact", encoded)
        self.assertEqual("c" * 64, record["identity"]["trusted_context_hash"])
        self.assertIn("[redacted:", str(record["request"]["context"]["trusted_context"]))

    def test_record_is_complete_for_a_decided_snapshot(self):
        request = snapshot(state="simulated", updated_at=150, execution_possible=False)
        request["gates"][2] = {"id": "approval", "kind": "approval", "status": "approved",
                               "evidence": {"evidence_id": "approval_1", "approval_gate_id": "approval",
                                            "request_id": request["request_id"], "actor": "control",
                                            "decision": "approve", "assurance": "ask",
                                            "request_hash": request["request_hash"],
                                            "expires_at": 700, "consumed_at": 150}}
        request["gates"][3] = {"id": "execute", "kind": "execute", "status": "simulated",
                               "evidence": {"tool": "semantic.action.home.tv.power_off", "arguments_hash": "d" * 64}}
        request["would_call"] = {"tool": "semantic.action.home.tv.power_off", "arguments": {"target": "living-room-tv"}}
        request["auto_approval"] = {"matched": False, "reason_code": "no_standing_rule",
                                    "reason": "No standing simulation-only rule is declared."}
        audit = [
            {"seq": 1, "request_id": request["request_id"], "event": "requested", "actor": "agent", "at": 100, "metadata": {}},
            {"seq": 2, "request_id": request["request_id"], "event": "approved", "actor": "control", "at": 150,
             "metadata": {"decision": "approve", "request_hash": request["request_hash"]}},
        ]
        notices = [{"notification_id": "notice_abc", "recipient": "human_owner", "state": "delivered",
                    "attempts": 2, "created_at": 100, "delivered_at": 120, "next_attempt_at": 160,
                    "claim_token": "deadbeefcafef00d", "last_error": None}]
        telemetry = [{"event_id": "call-1", "correlation_id": request["request_id"], "phase": "completed",
                      "operation": "desktop.app.close", "semantic_class": "desktop.control", "outcome": "failed",
                      "occurred_at": 149, "principal": "agent", "metadata": {"error_type": "timeout"}}]
        record = build_semantic_record(request, catalog=CATALOG, node="node-example-1",
                                       audit_events=audit, notifications=notices, telemetry=telemetry)

        self.assertEqual(request["request_id"], record["identity"]["request_id"])
        self.assertEqual(request["request_hash"], record["identity"]["request_hash"])
        self.assertEqual("unit-one", record["identity"]["idempotency_key"])
        self.assertEqual("c" * 64, record["identity"]["trusted_context_hash"])

        catalogue = record["catalogue"]
        self.assertEqual("home.tv.power_off", catalogue["action"])
        self.assertTrue(catalogue["catalogued"])
        self.assertEqual("home", catalogue["domain"])
        self.assertEqual("Turn off the allowlisted TV", catalogue["summary"])
        self.assertEqual("external_write", catalogue["effect"])
        self.assertEqual("R2", catalogue["risk"])
        self.assertEqual("automatic", catalogue["gate_class"])
        self.assertEqual(["household_presence"], catalogue["privacy_classes"])
        self.assertEqual(["allowlisted devices only"], catalogue["constraints"])

        # Free-text request content fails closed to fingerprints; the schema-safe target renders.
        self.assertTrue(record["request"]["summary"].startswith("[redacted:"))
        self.assertIn("sha256=", record["request"]["summary"])
        self.assertNotIn("Turn TV off", canonical_record_json(record))
        self.assertEqual("living-room-tv", record["request"]["target"])
        self.assertTrue(record["request"]["details"]["room"].startswith("[redacted:"))
        self.assertNotIn("lounge", canonical_record_json(record))
        self.assertEqual("agent", record["principal"]["requester"])
        self.assertEqual("node-example-1", record["principal"]["node"])
        self.assertEqual({"minimum_control": "policy", "policy_control": "ask", "effective_control": "ask"},
                         record["control"])

        self.assertTrue(record["auto_approval"]["evaluated"])
        self.assertIs(False, record["auto_approval"]["matched"])
        self.assertEqual("no_standing_rule", record["auto_approval"]["reason_code"])
        self.assertIs(False, record["auto_approval"]["authorizes_execution"])

        self.assertEqual(["schema", "notify", "approval", "execute"], [gate["id"] for gate in record["gates"]])
        self.assertEqual(["passed", "passed", "approved", "simulated"], [gate["status"] for gate in record["gates"]])

        delivery = record["notification_delivery"]
        self.assertEqual("delivered", delivery["state"])
        self.assertEqual(1, len(delivery["notices"]))
        self.assertEqual("notice_abc", delivery["notices"][0]["notification_id"])
        self.assertNotIn("deadbeefcafef00d", canonical_record_json(record))

        timestamps = record["timestamps"]
        self.assertEqual(100, timestamps["created_at"])
        self.assertEqual("1970-01-01T00:01:40Z", timestamps["created_at_utc"])
        self.assertEqual(150, timestamps["updated_at"])
        self.assertEqual(700, timestamps["approval_expires_at"])
        self.assertEqual(150, timestamps["decided_at"])

        self.assertTrue(record["decision"]["decided"])
        self.assertEqual("control", record["decision"]["actor"])
        self.assertEqual("ask", record["decision"]["assurance"])

        outcome = record["outcome"]
        self.assertEqual("simulated", outcome["state"])
        self.assertTrue(outcome["terminal"])
        self.assertIs(False, outcome["execution_possible"])
        self.assertIs(False, outcome["authorizes_execution"])
        self.assertEqual("semantic.action.home.tv.power_off", outcome["would_call_tool"])
        self.assertEqual("d" * 64, outcome["arguments_hash"])

        self.assertEqual([1, 2], [row["seq"] for row in record["audit"]])
        self.assertEqual("approved", record["audit"][1]["event"])
        self.assertEqual(1, len(record["linked_telemetry"]))
        self.assertEqual("desktop.app.close", record["linked_telemetry"][0]["operation"])
        self.assertEqual("tool timed out", record["linked_telemetry"][0]["label"])

    def test_render_escapes_adversarial_keys_and_values(self):
        request = snapshot()
        request["parameters"]["details"] = {"</pre><script>alert(1)</script>": "<img src=x>&\"'"}
        record = build_semantic_record(request, catalog=CATALOG)
        fragment = render_semantic_record_html(record, detail_href="/admin/requests/" + request["request_id"])
        self.assertNotIn("<script", fragment)
        self.assertNotIn("alert(1)", fragment)
        self.assertNotIn("img src", fragment)
        self.assertIn("[redacted key:", fragment)
        self.assertEqual(1, fragment.count("<pre"))
        self.assertEqual(1, fragment.count("</pre>"))
        self.assertIn("Full semantic record", fragment)
        self.assertIn("/admin/requests/" + request["request_id"], fragment)

    def test_canonical_json_is_deterministic_and_parseable(self):
        first = build_semantic_record(snapshot(), catalog=CATALOG)
        second = build_semantic_record(dict(reversed(list(snapshot().items()))), catalog=CATALOG)
        self.assertEqual(canonical_record_json(first), canonical_record_json(second))
        self.assertEqual(first, json.loads(canonical_record_json(first)))

    def test_gate_evidence_uses_a_closed_allowlist_and_unknown_fields_fail_closed(self):
        request = snapshot()
        request["gates"].append({"id": "probe", "kind": "tool", "status": "failed", "evidence": {
            "tool": "home.tv.status", "error_type": "RuntimeError",
            "providerResponse": "401 body with token sk-abc123",
            "result": {"stdout": "raw command output", "rows": 3},
        }})
        record = build_semantic_record(request, catalog=CATALOG)
        encoded = canonical_record_json(record)
        probe = record["gates"][-1]["evidence"]
        self.assertEqual("home.tv.status", probe["tool"])
        self.assertEqual("RuntimeError", probe["error_type"])
        self.assertTrue(str(probe["providerResponse"]).startswith("[redacted:"))
        self.assertTrue(str(probe["result"]["stdout"]).startswith("[redacted:"))
        self.assertEqual(3, probe["result"]["rows"])
        for leaked in ("401 body", "sk-abc123", "raw command output"):
            with self.subTest(leaked=leaked):
                self.assertNotIn(leaked, encoded)

    def test_execution_result_postconditions_audit_metadata_and_idempotency_fail_closed(self):
        request = snapshot(state="executed", idempotency_key="two words here")
        request["execution_result"] = {"output": "raw provider output", "count": 2}
        request["postconditions"] = {"verified_note": "free text postcondition"}
        audit = [{"seq": 1, "request_id": request["request_id"], "event": "requested", "actor": "agent",
                  "at": 100, "metadata": {"customField": "arbitrary audit text", "decision": "approve"}}]
        record = build_semantic_record(request, catalog=CATALOG, audit_events=audit)
        encoded = canonical_record_json(record)
        for leaked in ("raw provider output", "free text postcondition", "arbitrary audit text",
                       "two words here"):
            with self.subTest(leaked=leaked):
                self.assertNotIn(leaked, encoded)
        self.assertTrue(record["outcome"]["execution_result"]["output"].startswith("[redacted:"))
        self.assertEqual(2, record["outcome"]["execution_result"]["count"])
        self.assertTrue(record["outcome"]["postconditions"]["verified_note"].startswith("[redacted:"))
        self.assertEqual("approve", record["audit"][0]["metadata"]["decision"])
        self.assertTrue(record["audit"][0]["metadata"]["customField"].startswith("[redacted:"))
        self.assertTrue(record["identity"]["idempotency_key"].startswith("[redacted:"))
        self.assertIn("sha256=", record["identity"]["idempotency_key"])
        secret_key = build_semantic_record(snapshot(idempotency_key="Bearer sk-verysecret"), catalog=CATALOG)
        self.assertIn("secret material", secret_key["identity"]["idempotency_key"])
        self.assertNotIn("sk-verysecret", canonical_record_json(secret_key))

    def test_notification_last_error_becomes_redaction_metadata(self):
        notices = [{"notification_id": "notice_abc", "recipient": "human_owner", "state": "pending",
                    "attempts": 3, "created_at": 100, "delivered_at": None, "next_attempt_at": 160,
                    "last_error": "401 unauthorized: token tok-secret-999 rejected"}]
        record = build_semantic_record(snapshot(), catalog=CATALOG, notifications=notices)
        encoded = canonical_record_json(record)
        self.assertNotIn("tok-secret-999", encoded)
        self.assertNotIn("401 unauthorized", encoded)
        last_error = record["notification_delivery"]["notices"][0]["last_error"]
        self.assertIn("[redacted: provider error content", last_error)
        self.assertIn("sha256=", last_error)

    def test_gate_audit_and_telemetry_inputs_are_capped_before_processing(self):
        request = snapshot()
        gates = CountingIterable({"id": f"gate{index:05}", "kind": "condition", "status": "passed",
                                  "evidence": {"actual": index}} for index in range(10_000))
        audit = CountingIterable({"seq": index, "request_id": request["request_id"], "event": "requested",
                                  "actor": "agent", "at": 100 + index, "metadata": {}}
                                 for index in range(10_000))
        telemetry = CountingIterable({"event_id": f"call-{index}", "correlation_id": request["request_id"],
                                      "phase": "completed", "operation": "desktop.app.close",
                                      "semantic_class": "desktop.control", "outcome": "succeeded",
                                      "occurred_at": 99, "metadata": {}} for index in range(10_000))
        notifications = CountingIterable({"notification_id": f"notice_{index:06x}", "recipient": "human_owner",
                                          "state": "pending", "attempts": 1, "created_at": index,
                                          "delivered_at": None, "next_attempt_at": index, "last_error": None}
                                         for index in range(10_000))
        request["gates"] = gates
        record = build_semantic_record(request, catalog=CATALOG, audit_events=audit,
                                       notifications=notifications, telemetry=telemetry)
        self.assertEqual(MAX_GATES, len(record["gates"]))
        self.assertEqual(MAX_AUDIT, len(record["audit"]))
        self.assertEqual(MAX_TELEMETRY, len(record["linked_telemetry"]))
        self.assertEqual(MAX_NOTICES, len(record["notification_delivery"]["notices"]))
        self.assertEqual({"gates": True, "audit_events": True, "linked_telemetry": True, "notices": True},
                         record["omissions"])
        # Consumption is bounded before any traversal: exactly cap + 1 items are
        # pulled from each 10k-item adversarial iterable (one extra proves truncation).
        self.assertEqual(MAX_GATES + 1, gates.consumed)
        self.assertEqual(MAX_AUDIT + 1, audit.consumed)
        self.assertEqual(MAX_TELEMETRY + 1, telemetry.consumed)
        self.assertEqual(MAX_NOTICES + 1, notifications.consumed)

    def test_untruncated_inputs_report_no_omissions(self):
        record = build_semantic_record(snapshot(), catalog=CATALOG,
                                       audit_events=[{"seq": 1, "event": "requested", "actor": "agent",
                                                      "at": 100, "metadata": {}}])
        self.assertEqual({"gates": False, "audit_events": False, "linked_telemetry": False,
                          "notices": False}, record["omissions"])

    def test_notifications_iterator_is_consumed_once_for_notices_and_delivery(self):
        def rows():
            yield {"notification_id": "notice_abc", "recipient": "human_owner", "state": "delivered",
                   "attempts": 2, "created_at": 100, "delivered_at": 120, "next_attempt_at": 160,
                   "last_error": None}
            yield {"notification_id": "notice_def", "recipient": "human_owner", "state": "pending",
                   "attempts": 1, "created_at": 101, "delivered_at": None, "next_attempt_at": 161,
                   "last_error": None}
        record = build_semantic_record(snapshot(), catalog=CATALOG, notifications=rows())
        delivery = record["notification_delivery"]
        # Both projections must see the same bounded rows; a drained one-shot
        # iterator would leave the summary claiming "none" beside two notices.
        self.assertEqual(2, len(delivery["notices"]))
        self.assertEqual("pending", delivery["state"])
        self.assertEqual(2, delivery["attempts"])
        self.assertIs(False, record["omissions"]["notices"])

    def test_notification_recipients_require_catalogue_presentation_authorization(self):
        rows = [{"notification_id": "notice_abc", "recipient": "unschema-recipient@example.test",
                 "state": "delivered", "attempts": 1, "created_at": 100,
                 "delivered_at": 101, "next_attempt_at": None, "last_error": None}]
        hidden = build_semantic_record(snapshot(), catalog=CATALOG, notifications=rows)
        rendered = hidden["notification_delivery"]["notices"][0]["recipient"]
        self.assertIn("[redacted: notification recipient not presentation-authorized", rendered)
        self.assertNotIn("unschema-recipient@example.test", canonical_record_json(hidden))

        authorized_catalogue = deepcopy(CATALOG)
        authorized_catalogue["actions"]["home.tv.power_off"][
            "presentation_safe_notification_recipients"] = ["human_owner"]
        allowed_rows = [{**rows[0], "recipient": "human_owner"}]
        shown = build_semantic_record(snapshot(), catalog=authorized_catalogue, notifications=allowed_rows)
        self.assertEqual("human_owner", shown["notification_delivery"]["notices"][0]["recipient"])

        gate_snapshot = snapshot(gates=[{
            "id": "notify", "kind": "notify", "status": "passed",
            "evidence": {"recipient": "unschema-recipient@example.test", "delivered": True}}])
        hidden_gate = build_semantic_record(gate_snapshot, catalog=CATALOG)
        self.assertNotIn("unschema-recipient@example.test", canonical_record_json(hidden_gate))
        shown_gate = build_semantic_record(gate_snapshot, catalog=authorized_catalogue)
        self.assertIn("[redacted: notification recipient not presentation-authorized",
                      shown_gate["gates"][0]["evidence"]["recipient"])
        authorized_gate = deepcopy(gate_snapshot)
        authorized_gate["gates"][0]["evidence"]["recipient"] = "human_owner"
        shown_authorized_gate = build_semantic_record(authorized_gate, catalog=authorized_catalogue)
        self.assertEqual("human_owner", shown_authorized_gate["gates"][0]["evidence"]["recipient"])

    def test_closed_slug_fields_screen_entropy_and_render_only_known_ids_and_enums(self):
        entropy_token = "A1b2C3d4E5f6G7h8J9k0L1m2"
        credential = "ghp_" + "A1b2C3d4" * 5
        notice_id = "notice_" + "0123456789abcdef" * 4
        evidence_id = "approval_" + "ab01" * 8
        request = snapshot()
        request["gates"].append({"id": "probe", "kind": "tool", "status": "failed", "evidence": {
            "error_type": entropy_token, "reason": credential, "recipient": "user-" + entropy_token,
            "notification_id": notice_id, "evidence_id": evidence_id,
            "decision": "approve", "assurance": entropy_token,
        }})
        record = build_semantic_record(request, catalog=CATALOG)
        encoded = canonical_record_json(record)
        for leaked in (entropy_token, credential):
            with self.subTest(leaked=leaked):
                self.assertNotIn(leaked, encoded)
        for prefix in ("tag:", "owner@", "scope/", "kind."):
            punctuated = build_semantic_record(snapshot(gates=[{
                "id": "probe", "kind": "tool", "status": "failed",
                "evidence": {"error_type": prefix + entropy_token}}]), catalog=CATALOG)
            self.assertNotIn(prefix + entropy_token, canonical_record_json(punctuated))
            self.assertIn("secret material", punctuated["gates"][0]["evidence"]["error_type"])
        evidence = record["gates"][-1]["evidence"]
        # High-entropy strings in closed slug/enum positions collapse to the
        # secret-material marker, never a hash of the credential.
        for field in ("error_type", "reason", "recipient", "assurance"):
            with self.subTest(field=field):
                self.assertIn("secret material", evidence[field])
                self.assertNotIn("sha256=", evidence[field])
        # Explicit host digest shapes and known enum values still render exactly.
        self.assertEqual(notice_id, evidence["notification_id"])
        self.assertEqual(evidence_id, evidence["evidence_id"])
        self.assertEqual("approve", evidence["decision"])
        low_entropy = build_semantic_record(snapshot(gates=[{
            "id": "g", "kind": "approval", "status": "waiting",
            "evidence": {"decision": "maybe"}}]), catalog=CATALOG)
        self.assertIn("[redacted:", low_entropy["gates"][0]["evidence"]["decision"])
        self.assertIn("sha256=", low_entropy["gates"][0]["evidence"]["decision"])
        unhashable = build_semantic_record(snapshot(gates=[{
            "id": "g", "kind": "approval", "status": "waiting",
            "evidence": {"decision": {"nested": "value"}}}]), catalog=CATALOG)
        self.assertEqual("[redacted: invalid enum field]",
                         unhashable["gates"][0]["evidence"]["decision"])

    def test_top_level_slug_positions_also_screen_entropy(self):
        entropy_token = "A1b2C3d4E5f6G7h8J9k0L1m2"
        tainted = snapshot(blocked_by=entropy_token)
        audit = [{"seq": 1, "request_id": tainted["request_id"], "event": "requested",
                  "actor": entropy_token, "at": 100, "metadata": {}}]
        record = build_semantic_record(tainted, catalog=CATALOG, audit_events=audit)
        self.assertIsNone(record["outcome"]["blocked_by"])
        self.assertEqual("not recorded", record["audit"][0]["actor"])
        self.assertNotIn(entropy_token, canonical_record_json(record))
        # Host request identifiers remain renderable (prefixed hex digest shape).
        self.assertEqual(tainted["request_id"], record["identity"]["request_id"])

    def test_linked_telemetry_reuses_strict_entropy_screening(self):
        entropy_token = "A1b2C3d4E5f6G7h8J9k0L1m2"
        telemetry = [{"event_id": "event." + entropy_token,
                      "correlation_id": "correlation/" + entropy_token,
                      "phase": "completed", "operation": "tag:" + entropy_token,
                      "semantic_class": "kind." + entropy_token, "outcome": "state@" + entropy_token,
                      "principal": "owner/" + entropy_token, "occurred_at": 100, "metadata": {}}]
        record = build_semantic_record(snapshot(), catalog=CATALOG, telemetry=telemetry)
        encoded = canonical_record_json(record)
        self.assertNotIn(entropy_token, encoded)
        for field in ("operation", "semantic_class", "outcome", "principal", "correlation_id", "event_id"):
            with self.subTest(field=field):
                self.assertEqual("not recorded", record["linked_telemetry"][0][field])

    def test_per_section_and_total_byte_bounds_fail_closed_with_markers(self):
        record = build_semantic_record(snapshot(), catalog=CATALOG)
        squeezed = enforce_record_bounds(record, section_max_bytes=64)
        self.assertIn("redacted", squeezed["gates"])
        self.assertIn("sha256", squeezed["gates"])
        self.assertIn("bytes", squeezed["gates"])
        minimal = enforce_record_bounds(record, record_max_bytes=256)
        self.assertIn("[redacted:", minimal["redacted"])
        self.assertEqual(record["identity"], minimal["identity"])
        self.assertEqual({"record_version", "identity", "redacted", "bytes"}, set(minimal))

    def test_oversized_execution_result_never_reaches_the_rendered_record(self):
        request = snapshot(state="executed")
        request["execution_result"] = {"rows": [[list(range(32)) for _ in range(32)] for _ in range(32)]}
        record = build_semantic_record(request, catalog=CATALOG)
        outcome = record["outcome"]
        self.assertIn("redacted", outcome)
        self.assertIn("serialized bytes", outcome["redacted"])
        fragment = render_semantic_record_html(record)
        self.assertLess(len(fragment.encode()), 400_000)


class UniqueDelivered:
    """Delivered notifier for several requests; raises for a poisoned summary."""

    def notify(self, request, gate):
        if request["parameters"].get("summary") == "boom":
            raise RuntimeError("provider exploded")
        return {"delivered": True, "notification_id": "notice_" + request["request_hash"][:16],
                "request_id": request["request_id"], "request_hash": request["request_hash"],
                "notification_gate_id": gate["id"], "recipient": gate["recipient"],
                "template_hash": hashlib.sha256(gate["template"].encode()).hexdigest(), "delivered_at": 100}


class SemanticRecordPanelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        credentials = self.root / "credentials.json"
        credentials.write_text(json.dumps({"credentials": {"device": {"adapter": "example", "kind": "token", "value": "never-render-me"}}}))
        self.credentials = CredentialRegistry(credentials)
        self.authority = CapabilityAuthority(bytes.fromhex("33" * 32), PRINCIPALS)
        self.agent = {"Authorization": f"Bearer {self.authority.token_for('agent')}"}
        self.agent_two = {"Authorization": f"Bearer {self.authority.token_for('agent-two')}"}
        self.app, self.ledger, self.control = self.build_app("ledger.sqlite3")

    def tearDown(self):
        self.ledger.close()
        self.tmp.cleanup()

    def build_app(self, database, *, auto_approval=None):
        backend = CoreBackend(build_policy(CATALOG, PRINCIPALS), approval_key=bytes.fromhex("22" * 32),
                              clock=lambda: 100, notifier=UniqueDelivered(),
                              auto_approval=auto_approval, catalog=CATALOG if auto_approval else None)
        ledger = Ledger(self.root / database)
        control = GateControl(backend, ledger, clock=lambda: 100)
        app = SemanticGateApplication(control, self.authority, self.credentials, catalog=CATALOG,
                                      admin_password="correct horse battery staple",
                                      origins=["https://control.example"], clock=lambda: 100,
                                      principal_contexts=PRINCIPALS)
        return app, ledger, control

    def call(self, app, method, path, headers=None, payload=None):
        return app.handle(method, path, headers or {}, b"" if payload is None else json.dumps(payload).encode())

    def login(self, app):
        login = self.call(app, "POST", "/login", payload={"username": "control", "password": "correct horse battery staple"})
        cookie = login.headers["Set-Cookie"].split(";", 1)[0]
        return {"Cookie": cookie}, {"Cookie": cookie, "Origin": "https://control.example",
                                    "X-CSRF-Token": login.headers["X-CSRF-Token"]}

    def propose(self, app, key, *, action="home.tv.power_off", parameters=None, headers=None):
        payload = {"action": action,
                   "parameters": parameters or {"summary": "Turn TV off", "target": "living-room-tv", "details": {}},
                   "context": {}, "idempotency_key": key}
        response = self.call(app, "POST", "/api/v1/requests", headers or self.agent, payload)
        self.assertEqual(201, response.status)
        return response.json()

    def test_panel_and_detail_route_expose_records_for_every_state(self):
        session, admin = self.login(self.app)
        expired = self.propose(self.app, "state-expired")
        self.ledger.expire_unresolved(now=150)
        approved = self.propose(self.app, "state-approved")
        self.assertEqual("simulated", self.call(self.app, "POST", f"/admin/requests/{approved['request_id']}/approve",
                                                admin, approved["approval_challenge"]).json()["state"])
        denied = self.propose(self.app, "state-denied")
        self.assertEqual("denied", self.call(self.app, "POST", f"/admin/requests/{denied['request_id']}/deny",
                                             admin, denied["approval_challenge"]).json()["state"])
        cancelled = self.propose(self.app, "state-cancelled")
        self.assertEqual("cancelled", self.call(self.app, "POST", f"/api/v1/requests/{cancelled['request_id']}/cancel",
                                                self.agent).json()["state"])
        failed = self.propose(self.app, "state-failed",
                              parameters={"summary": "boom", "target": "living-room-tv", "details": {}})
        self.assertEqual("failed", failed["state"])
        waiting = self.propose(self.app, "state-waiting")
        self.assertEqual("waiting_for_approval", waiting["state"])

        panel = self.call(self.app, "GET", "/", session).body.decode()
        self.assertGreaterEqual(panel.count("Full semantic record"), 6)
        self.assertNotIn("<script", panel)

        expectations = {
            expired["request_id"]: ('"state": "expired"',),
            approved["request_id"]: ('"state": "simulated"', '"actor": "control"', '"assurance": "ask"',
                                     '"decided": true'),
            denied["request_id"]: ('"state": "denied"',),
            cancelled["request_id"]: ('"state": "cancelled"',),
            failed["request_id"]: ('"state": "failed"', '"error_type": "RuntimeError"'),
            waiting["request_id"]: ('"state": "waiting_for_approval"', '"approval_expires_at": 700'),
        }
        for request_id, expected in expectations.items():
            page = self.call(self.app, "GET", f"/admin/requests/{request_id}", session)
            self.assertEqual(200, page.status)
            text = page.body.decode()
            self.assertIn("Full semantic record", text)
            self.assertNotIn("<script", text)
            for needle in ('"gate_class": "automatic"', '"household_presence"', '"allowlisted devices only"',
                           '"requester": "agent"', '"node": "node-example-1"', '"policy_control": "ask"',
                           '"effective_control": "ask"', '"minimum_control": "policy"',
                           '"trusted_context_hash"', '"execution_possible": false',
                           '"authorizes_execution": false', request_id) + expected:
                with self.subTest(request=request_id, needle=needle):
                    self.assertIn(needle, text)
        approved_page = self.call(self.app, "GET", f"/admin/requests/{approved['request_id']}", session).body.decode()
        self.assertIn('"idempotency_key": "state-approved"', approved_page)
        self.assertIn(approved["request_hash"], approved_page)

    def test_detail_route_authorization_nonexistent_and_other_principal(self):
        request = self.propose(self.app, "authz-one")
        unauthenticated = self.call(self.app, "GET", f"/admin/requests/{request['request_id']}")
        self.assertEqual(303, unauthenticated.status)
        self.assertEqual("/login", unauthenticated.headers["Location"])
        bearer_only = self.call(self.app, "GET", f"/admin/requests/{request['request_id']}", self.agent)
        self.assertEqual(303, bearer_only.status)
        session, _ = self.login(self.app)
        self.assertEqual(404, self.call(self.app, "GET", "/admin/requests/req_doesnotexist000000", session).status)
        self.assertEqual(404, self.call(self.app, "GET", "/admin/requests/..%2F..%2Fetc", session).status)
        self.assertEqual(200, self.call(self.app, "GET", f"/admin/requests/{request['request_id']}", session).status)
        other = self.call(self.app, "GET", f"/api/v1/requests/{request['request_id']}", self.agent_two)
        self.assertEqual(400, other.status)
        self.assertIn("cannot access", other.json()["error"])
        listed = self.call(self.app, "GET", "/api/v1/requests", self.agent_two).json()
        self.assertEqual([], [item for item in listed if item["request_id"] == request["request_id"]])

    def test_record_redacts_secrets_and_escapes_adversarial_content_end_to_end(self):
        session, _ = self.login(self.app)
        parameters = {"summary": "Email supplier", "target": "support@example.test", "details": {
            "api_token": "tok-secret-123",
            "body": "the raw outbound message body",
            "command": "rm -rf /",
            "draft_note": "schema-marked private detail",
            "</pre><script>alert(1)</script>": "<script>alert(2)</script>",
            "nested": [{"password": "hunter2"}, {"authorization": "Bearer abc123"}],
        }}
        request = self.propose(self.app, "redact-one", action="communication.send", parameters=parameters)
        self.ledger.enqueue_notification(request_id=request["request_id"], request_hash=request["request_hash"],
                                         notify_gate_id="notify", recipient="human_owner",
                                         template_hash="a" * 64, now=100)
        claimed = self.ledger.claim_notification(now=100, lease_seconds=60)
        page = self.call(self.app, "GET", f"/admin/requests/{request['request_id']}", session).body.decode()
        self.assertIn("[redacted:", page)
        for secret in ("tok-secret-123", "the raw outbound message body", "rm -rf /", "hunter2",
                       "Bearer abc123", "schema-marked private detail", "never-render-me",
                       claimed["claim_token"], "authenticated_principal"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, page)
        self.assertNotIn("<script", page)
        self.assertNotIn("alert(1)", page)
        self.assertNotIn("alert(2)", page)
        self.assertIn("[redacted key:", page)
        self.assertIn("notice_", page)

    def test_auto_approval_match_and_non_match_reasons_appear_in_the_record(self):
        standing = AutoApprovalPolicy({"version": 5, "enabled": True, "rules": [], "global_simulation_rule": {
            "rule_id": "rule-global-simulation", "version": 1,
            "human_gate_classes": ["human_communication", "human_spending"],
            "requesters": ["agent"], "nodes": ["node-example-1"],
            "expires_at": 86_500, "review_by": 3_700}})
        app, ledger, _control = self.build_app("auto.sqlite3", auto_approval=standing)
        try:
            session, _ = self.login(app)
            matched = self.propose(app, "auto-match")
            self.assertEqual("simulated", matched["state"])
            page = self.call(app, "GET", f"/admin/requests/{matched['request_id']}", session).body.decode()
            for needle in ('"matched": true', '"rule_id": "rule-global-simulation"', '"rule_version": 1',
                           '"reason_code": "matched_global_simulation_scope"', '"authorizes_execution": false'):
                with self.subTest(needle=needle):
                    self.assertIn(needle, page)
            gated = self.propose(app, "auto-gated", action="communication.send",
                                 parameters={"summary": "Ask supplier", "target": "support@example.test", "details": {}})
            self.assertEqual("waiting_for_approval", gated["state"])
            gated_page = self.call(app, "GET", f"/admin/requests/{gated['request_id']}", session).body.decode()
            self.assertIn('"matched": false', gated_page)
            self.assertIn("communication_requires_human", gated_page)
        finally:
            ledger.close()

    def test_telemetry_linked_observations_appear_in_the_record(self):
        session, _ = self.login(self.app)
        request = self.propose(self.app, "telemetry-one")
        observation = {"event_id": "tool-9", "correlation_id": request["request_id"], "phase": "completed",
                       "operation": "desktop.app.close", "semantic_class": "desktop.control", "outcome": "failed",
                       "occurred_at": 99, "metadata": {"error_type": "timeout"}}
        self.assertEqual(200, self.call(self.app, "POST", "/api/v1/audit-observations", self.agent, observation).status)
        page = self.call(self.app, "GET", f"/admin/requests/{request['request_id']}", session).body.decode()
        self.assertIn("linked_telemetry", page)
        self.assertIn("desktop.app.close", page)
        self.assertIn("tool timed out", page)

    def test_history_keeps_all_feeds_and_gains_state_filters(self):
        session, admin = self.login(self.app)
        denied = self.propose(self.app, "filter-denied")
        self.call(self.app, "POST", f"/admin/requests/{denied['request_id']}/deny", admin, denied["approval_challenge"])
        cancelled = self.propose(self.app, "filter-cancelled")
        self.call(self.app, "POST", f"/api/v1/requests/{cancelled['request_id']}/cancel", self.agent)
        panel = self.call(self.app, "GET", "/", session).body.decode()
        for expected in ("?state=denied", "?state=cancelled", "?feed=denials", "?feed=telemetry",
                         "Completed history", denied["request_id"], cancelled["request_id"]):
            with self.subTest(expected=expected):
                self.assertIn(expected, panel)
        filtered = self.call(self.app, "GET", "/?state=denied", session).body.decode()
        history = filtered[filtered.index("Completed history"):filtered.index("Emergency controls")]
        self.assertIn(denied["request_id"], history)
        self.assertNotIn(cancelled["request_id"], history)
        self.assertEqual(400, self.call(self.app, "GET", "/?state=bogus", session).status)

    def test_decision_forms_and_no_javascript_survive_the_record_feature(self):
        session, _ = self.login(self.app)
        pending = self.propose(self.app, "still-no-js")
        panel = self.call(self.app, "GET", "/", session).body.decode()
        self.assertIn(f"action='/admin/requests/{pending['request_id']}/approve'", panel)
        self.assertIn(f"action='/admin/requests/{pending['request_id']}/deny'", panel)
        self.assertIn("Full semantic record", panel)
        self.assertNotIn("<script", panel)
        self.assertNotIn("javascript:", panel)
        detail = self.call(self.app, "GET", f"/admin/requests/{pending['request_id']}", session).body.decode()
        self.assertNotIn("<script", detail)
        self.assertIn("<pre", detail)


if __name__ == "__main__":
    unittest.main()
