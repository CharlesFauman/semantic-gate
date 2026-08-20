#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import unittest

from semantic_gate.controller import GateControl
from semantic_gate.projection import (
    CARD_TEXT_LIMIT,
    classify_observation,
    collapse_observations,
    partition_audit_events,
    NOT_DECLARED,
    PRESENTATION_FIELDS,
    WITHHELD,
    build_decision_card,
    decision_card_audit_labels,
    render_decision_card_html,
    render_decision_card_text,
    summarize_delivery,
)

NOW = 1_700_000_000
HASH = "a1b2c3d4" + "e" * 56

CATALOG = {"actions": {"communication.send": {
    "risk": "R2", "effect": "write", "summary": "Send one reviewed message",
    "presentation": {
        "proposed_effect": "Send one email to the reviewed supplier address",
        "reason": "The purchase needs written supplier confirmation",
        "node": "node-example-2",
        "safe_target_field": "target",
        "safe_target_values": ["support@example.test"],
        "spends": False, "communicates": True, "changes_state": False,
        # Unknown keys are not part of the closed presentation contract and must never project.
        "prompt": "system prompt text that must stay private",
        "body": "Hello supplier, please confirm parts",
        "command": "rm -rf /",
    }}}}

SENSITIVE = (
    "free text written by the model", "Hello supplier, please confirm parts", "rm -rf /",
    "/opt/example/private-notes.txt", "example-token-value-never-project",
    "system prompt text that must stay private", "LIST-123", "requirements.pdf",
)


def request_snapshot(**overrides):
    request = {
        "request_id": "req_abc123",
        "request_hash": HASH,
        "action": "communication.send",
        "requester": "agent-1",
        "state": "waiting_for_approval",
        "created_at": NOW - 300,
        "policy_control": "ask",
        "minimum_control": "policy",
        "effective_control": "ask",
        "parameters": {
            "summary": "free text written by the model",
            "target": "support@example.test",
            "details": {
                "body": "Hello supplier, please confirm parts",
                "command": "rm -rf /",
                "path": "/opt/example/private-notes.txt",
                "token": "example-token-value-never-project",
                "listing_id": "LIST-123",
                "attachments": ["requirements.pdf"],
            },
        },
        "approval_challenge": {
            "request_id": "req_abc123", "request_hash": HASH,
            "approval_gate_id": "approval", "expires_at": NOW + 300,
        },
    }
    request.update(overrides)
    return request


def card(delivery=None, **overrides):
    return build_decision_card(request_snapshot(**overrides), catalog=CATALOG, now=NOW, delivery=delivery)


class DecisionCardTests(unittest.TestCase):
    def test_card_projects_the_useful_semantic_decision_fields(self):
        value = card()
        self.assertEqual("communication.send", value["action"])
        self.assertEqual("Send one email to the reviewed supplier address", value["proposed_effect"])
        self.assertEqual("support@example.test", value["safe_target"])
        self.assertEqual("The purchase needs written supplier confirmation", value["reason"])
        self.assertEqual("agent-1", value["requester"])
        self.assertEqual("node-example-2", value["node"])
        self.assertEqual("R2", value["risk"])
        self.assertEqual(("ask", "policy", "ask"), (value["policy_control"], value["caller_floor"], value["effective_control"]))
        self.assertEqual(("no", "yes", "no"), (value["spends_money"], value["communicates_externally"], value["changes_state"]))
        self.assertEqual("in 5 min", value["expiry_phrase"])
        self.assertEqual("urgent", value["urgency"])
        self.assertEqual("2023-11-14T22:18:20Z", value["expires_at_utc"])
        self.assertEqual("req_abc123", value["request_id"])
        self.assertEqual("a1b2c3d4eeee", value["request_hash_fingerprint"])
        self.assertIn("not a standing permission", value["approve_consequence"])
        self.assertIn("new proposal", value["deny_consequence"])
        self.assertIn("authenticated", value["panel_reference"])
        text = render_decision_card_text(value)
        self.assertIn("Action: communication.send", text)
        self.assertIn("Proposed effect: Send one email to the reviewed supplier address", text)
        self.assertIn("Safe target: support@example.test", text)
        self.assertIn("Reason: The purchase needs written supplier confirmation", text)
        self.assertIn("Requester: agent-1", text)
        self.assertIn("node-example-2", text)
        self.assertIn("Can communicate externally: yes", text)
        self.assertIn("Expires: in 5 min", text)
        self.assertIn("a1b2c3d4eeee", text)

    def test_card_never_projects_parameters_bodies_commands_paths_or_credentials(self):
        value = card()
        rendered = json.dumps(value, sort_keys=True) + render_decision_card_text(value) + render_decision_card_html(value)
        for secret in SENSITIVE:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, rendered)
        self.assertNotIn("parameters", value)
        self.assertNotIn("details", value)
        self.assertNotIn("context", value)

    def test_target_outside_the_schema_owned_allowlist_is_withheld(self):
        parameters = {"summary": "x", "target": "attacker-chosen-destination@example.test", "details": {}}
        value = card(parameters=parameters)
        self.assertEqual(WITHHELD, value["safe_target"])
        rendered = json.dumps(value) + render_decision_card_text(value) + render_decision_card_html(value)
        self.assertNotIn("attacker-chosen-destination", rendered)

    def test_undeclared_presentation_falls_back_to_withheld_and_possible_capability(self):
        value = build_decision_card(request_snapshot(action="unlisted.action"), catalog=CATALOG, now=NOW)
        self.assertEqual("unlisted.action", value["action"])
        self.assertEqual(WITHHELD, value["proposed_effect"])
        self.assertEqual(WITHHELD, value["reason"])
        self.assertEqual(WITHHELD, value["safe_target"])
        self.assertEqual("not declared", value["risk"])
        self.assertEqual("not declared", value["node"])
        for flag in ("spends_money", "communicates_externally", "changes_state"):
            with self.subTest(flag=flag):
                self.assertEqual(NOT_DECLARED, value[flag])

    def test_presentation_contract_is_closed_and_non_string_values_are_ignored(self):
        self.assertEqual(
            {"proposed_effect", "reason", "node", "safe_target_field", "safe_target_values",
             "spends", "communicates", "changes_state"},
            set(PRESENTATION_FIELDS),
        )
        catalog = {"actions": {"communication.send": {"risk": ["R2"], "presentation": {
            "proposed_effect": {"nested": "object"}, "reason": 17, "node": "node with spaces",
            "spends": "yes", "safe_target_field": ["target"], "safe_target_values": "support@example.test"}}}}
        value = build_decision_card(request_snapshot(), catalog=catalog, now=NOW)
        self.assertEqual(WITHHELD, value["proposed_effect"])
        self.assertEqual(WITHHELD, value["reason"])
        self.assertEqual(WITHHELD, value["safe_target"])
        self.assertEqual("not declared", value["risk"])
        self.assertEqual("not declared", value["node"])
        self.assertEqual(NOT_DECLARED, value["spends_money"])

    def test_long_and_hostile_presentation_values_are_bounded_and_sanitized(self):
        catalog = {"actions": {"communication.send": {"risk": "R2", "presentation": {
            "proposed_effect": "E" * 5000,
            "reason": "Line\r\none\x00two‮flip said \"go\" and 'now' <script>alert(1)</script>",
            "safe_target_field": "target", "safe_target_values": ["support@example.test"]}}}}
        value = build_decision_card(request_snapshot(), catalog=catalog, now=NOW)
        self.assertEqual(CARD_TEXT_LIMIT, len(value["proposed_effect"]))
        self.assertTrue(value["proposed_effect"].endswith("..."))
        reason = value["reason"]
        self.assertLessEqual(len(reason), CARD_TEXT_LIMIT)
        self.assertEqual("Line onetwoflip said \"go\" and 'now' scriptalert(1)/script", reason)
        for character in ("\x00", "\r", "\n", "\u202e", "<", ">", "&"):
            with self.subTest(character=character):
                self.assertNotIn(character, reason)
        html = render_decision_card_html(value)
        self.assertIn("&quot;go&quot;", html)
        self.assertIn("&#x27;now&#x27;", html)
        self.assertNotIn('"go"', html)
        text = render_decision_card_text(value)
        self.assertLessEqual(len(text), 3000)
        for field, projected in value.items():
            if isinstance(projected, str):
                with self.subTest(field=field):
                    self.assertLessEqual(len(projected), 400)

    def test_card_is_bound_to_the_exact_request_for_reaction_approval(self):
        value = card()
        self.assertTrue(value["decision_available"])
        self.assertEqual(
            {"request_id": "req_abc123", "request_hash": HASH, "approval_gate_id": "approval", "expires_at": NOW + 300},
            value["reaction_binding"],
        )
        self.assertNotIn("blanket", render_decision_card_text(value))
        self.assertIn("exactly this request", value["approve_consequence"])

    def test_missing_mismatched_or_expired_challenges_offer_no_decision_binding(self):
        challenge = request_snapshot()["approval_challenge"]
        for label, request in (
            ("missing", request_snapshot(approval_challenge=None)),
            ("hash mismatch", request_snapshot(approval_challenge={**challenge, "request_hash": "f" * 64})),
            ("id mismatch", request_snapshot(approval_challenge={**challenge, "request_id": "req_other"})),
            ("extra field", request_snapshot(approval_challenge={**challenge, "approve": True})),
            ("expired", request_snapshot(approval_challenge={**challenge, "expires_at": NOW})),
        ):
            with self.subTest(label=label):
                value = build_decision_card(request, catalog=CATALOG, now=NOW)
                self.assertIsNone(value["reaction_binding"])
                self.assertFalse(value["decision_available"])
                self.assertIn("authenticated", render_decision_card_text(value))

    def test_expiry_urgency_is_derived_deterministically(self):
        challenge = request_snapshot()["approval_challenge"]
        for offset, urgency, phrase in ((240, "urgent", "in 4 min"), (1200, "soon", "in 20 min"), (7200, "scheduled", "in 2 h 0 min"), (30, "urgent", "in 30 s")):
            with self.subTest(offset=offset):
                value = build_decision_card(request_snapshot(approval_challenge={**challenge, "expires_at": NOW + offset}), catalog=CATALOG, now=NOW)
                self.assertEqual(urgency, value["urgency"])
                self.assertEqual(phrase, value["expiry_phrase"])
        expired = build_decision_card(request_snapshot(approval_challenge={**challenge, "expires_at": NOW - 1}), catalog=CATALOG, now=NOW)
        self.assertEqual("expired", expired["urgency"])
        self.assertEqual("expired", expired["expiry_phrase"])

    def test_delivery_state_is_summarized_without_content(self):
        self.assertEqual("none", summarize_delivery([])["state"])
        self.assertIn("No durable notification record", summarize_delivery([])["message"])
        notices = [
            {"notification_id": "notice_aaa", "state": "delivered", "attempts": 1},
            {"notification_id": "notice_bbb", "state": "pending", "attempts": 3},
        ]
        pending = summarize_delivery(notices)
        self.assertEqual("pending", pending["state"])
        self.assertIn("will retry after provider recovery", pending["message"])
        self.assertEqual(["notice_aaa", "notice_bbb"], pending["notification_ids"])
        self.assertEqual(3, pending["attempts"])
        unknown = summarize_delivery(notices + [{"notification_id": "notice_ccc", "state": "unknown", "attempts": 2}])
        self.assertEqual("unknown", unknown["state"])
        self.assertIn("automatic retry stopped to prevent duplicates", unknown["message"])
        hostile = summarize_delivery([{"notification_id": "notice <script> body text", "state": "pending", "attempts": "many"}])
        self.assertEqual([], hostile["notification_ids"])
        self.assertEqual(0, hostile["attempts"])
        value = card(delivery=notices)
        self.assertEqual("pending", value["delivery_state"])
        self.assertIn("notice_bbb", render_decision_card_html(value))

    def test_audit_labels_are_content_minimized_and_ingestible(self):
        labels = decision_card_audit_labels(card())
        self.assertLessEqual(set(labels), GateControl.OBSERVATION_METADATA_KEYS)
        for key, value in labels.items():
            with self.subTest(key=key):
                self.assertTrue(re.fullmatch(r"[A-Za-z0-9_.:/-]{0,128}", str(value)))
        self.assertEqual("decision-card", labels["surface"])
        self.assertEqual("node-example-2", labels["node"])
        rendered = json.dumps(labels)
        for secret in SENSITIVE:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, rendered)


class FeedProjectionTests(unittest.TestCase):
    """Gate decisions, policy denials and ordinary tool telemetry are separate feeds."""

    @staticmethod
    def observation(**overrides):
        row = {"event_id": "call-1", "correlation_id": "corr-1", "principal": "agent-code-1",
               "phase": "completed", "operation": "code.edit_file", "semantic_class": "code.change.write",
               "outcome": "failed", "occurred_at": NOW, "metadata": {"surface": "harness", "error_type": "nonzero_exit"}}
        row.update(overrides)
        return row

    def test_ordinary_tool_outcomes_are_never_labelled_semantic_gate_failures(self):
        cases = (
            ({"outcome": "failed", "metadata": {"error_type": "nonzero_exit"}}, "nonzero exit"),
            ({"outcome": "failed", "metadata": {"error_type": "timeout"}}, "timed out"),
            ({"outcome": "failed", "metadata": {"error_type": "interrupted"}}, "interrupted"),
            ({"outcome": "cancelled", "metadata": {}}, "cancelled"),
            ({"outcome": "succeeded", "metadata": {}}, "succeeded"),
            ({"outcome": "unknown", "metadata": {}}, "unknown"),
        )
        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                row = classify_observation(self.observation(**overrides))
                self.assertEqual("execution_telemetry", row["category"])
                self.assertEqual("tool telemetry", row["source"])
                self.assertFalse(row["is_gate_failure"])
                self.assertFalse(row["is_policy_denial"])
                self.assertIn(expected, row["label"])
                self.assertNotIn("Semantic Gate", row["label"])
                self.assertNotIn("denied", row["label"])

    def test_duplicate_root_and_detail_observations_sharing_a_correlation_id_collapse_into_one_row(self):
        root = self.observation()
        detail = self.observation(event_id="call-1-detail", occurred_at=NOW + 2,
                                  semantic_class="code.change.write.detail")
        collapsed = collapse_observations([root, detail])
        self.assertEqual(1, len(collapsed))
        self.assertEqual(2, collapsed[0]["occurrences"])
        self.assertEqual("corr-1", collapsed[0]["correlation_id"])
        self.assertEqual(["call-1", "call-1-detail"], collapsed[0]["event_ids"])
        self.assertEqual("code.edit_file", collapsed[0]["operation"])
        self.assertEqual(NOW, collapsed[0]["first_seen_at"])
        self.assertEqual(NOW + 2, collapsed[0]["last_seen_at"])
        self.assertEqual("execution_telemetry", collapsed[0]["category"])
        separate = collapse_observations([root, detail, self.observation(event_id="call-2", correlation_id="corr-2")])
        self.assertEqual(2, len(separate))
        uncorrelated = collapse_observations([
            self.observation(event_id="call-3", correlation_id=None),
            self.observation(event_id="call-4", correlation_id=None)])
        self.assertEqual(2, len(uncorrelated))
        self.assertEqual([1, 1], [row["occurrences"] for row in uncorrelated])

    def test_audit_events_split_into_decisions_denials_gate_errors_withdrawals_and_service(self):
        events = [
            {"seq": 1, "event": "requested", "actor": "agent-code-1", "request_id": "req_1", "at": NOW, "metadata": {}},
            {"seq": 2, "event": "auto_approved", "actor": "policy", "request_id": "req_1", "at": NOW, "metadata": {"rule_id": "rule-global-simulation"}},
            {"seq": 3, "event": "denied", "actor": "control", "request_id": "req_2", "at": NOW, "metadata": {}},
            {"seq": 4, "event": "blocked", "actor": "agent-code-1", "request_id": "req_3", "at": NOW, "metadata": {}},
            {"seq": 5, "event": "cancelled", "actor": "agent-code-1", "request_id": "req_4", "at": NOW, "metadata": {}},
            {"seq": 6, "event": "failed", "actor": "agent-code-1", "request_id": "req_5", "at": NOW, "metadata": {}},
            {"seq": 7, "event": "control_changed", "actor": "control", "request_id": None, "at": NOW, "metadata": {"key": "pause_all"}},
            {"seq": 8, "event": "permission_observed", "actor": "agent-code-1", "request_id": None, "at": NOW, "metadata": {}},
        ]
        feeds = partition_audit_events(events)
        self.assertEqual({"decisions", "denials", "gate_errors", "withdrawn", "service"}, set(feeds))
        self.assertEqual([1, 2], [row["seq"] for row in feeds["decisions"]])
        self.assertEqual([3, 4], [row["seq"] for row in feeds["denials"]])
        self.assertEqual([5], [row["seq"] for row in feeds["withdrawn"]])
        self.assertEqual([6], [row["seq"] for row in feeds["gate_errors"]])
        self.assertEqual([7], [row["seq"] for row in feeds["service"]])
        self.assertTrue(all(row["source"] == "policy gate" for row in feeds["denials"]))
        self.assertEqual("coordinator control", feeds["service"][0]["source"])
        self.assertTrue(feeds["denials"][0]["is_policy_denial"])
        self.assertFalse(feeds["withdrawn"][0]["is_policy_denial"])
        self.assertFalse(feeds["decisions"][0]["is_policy_denial"])
        self.assertIn("rule-global-simulation", feeds["decisions"][1]["label"])
        self.assertIn("cancelled", feeds["withdrawn"][0]["label"])
        for lane in feeds.values():
            for row in lane:
                with self.subTest(row=row["seq"]):
                    self.assertLessEqual(len(row["label"]), 160)
                    self.assertNotIn("<", row["label"])


if __name__ == "__main__":
    unittest.main()
