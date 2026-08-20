#!/usr/bin/env python3
"""Adversarial tests for the policy-owned, default-deny auto-approval matcher."""
from __future__ import annotations

import unittest

from semantic_gate import autoapproval
from semantic_gate.autoapproval import (
    AutoApprovalPolicy,
    AutoApprovalPolicyError,
    approval_evidence,
    audit_metadata,
    commit_binding_valid,
    evaluate,
)
from semantic_gate.catalog import HUMAN_GATE_CLASSES

NOW = 1_700_000_000
HASH = "9f" * 32
COMMIT = "a" * 40

CODE_RULE = {
    "rule_id": "rule-code-work", "version": 4, "action_class": "code_edit",
    "actions": ["code.edit_file", "code.format_file"],
    "repository": "example-org/example-service",
    "refs": ["refs/heads/main", "refs/heads/feature/safe-work"],
    "requesters": ["agent-code-1"], "nodes": ["node-example-1"],
    "environments": [], "targets": [],
    "parameter_constraints": {"summary": {"enum": ["Apply reviewed patch"]}},
    "expires_at": NOW + 86_400, "review_by": NOW + 3_600,
}
PUSH_RULE = {
    "rule_id": "rule-normal-push", "version": 2, "action_class": "git_push",
    "actions": ["git.push"],
    "repository": "example-org/example-service",
    "refs": ["refs/heads/feature/safe-work"],
    "requesters": ["agent-code-1"], "nodes": ["node-example-1"],
    "environments": [], "targets": [],
    "parameter_constraints": {"force": {"enum": [False]}},
    "expires_at": NOW + 86_400, "review_by": NOW + 3_600,
}
DEPLOY_RULE = {
    "rule_id": "rule-staging-deploy", "version": 1, "action_class": "deploy",
    "actions": ["deploy.release"],
    "repository": "example-org/example-service",
    "refs": ["refs/heads/main"],
    "requesters": ["agent-code-1"], "nodes": ["node-example-1"],
    "environments": ["staging"], "targets": ["staging-cluster"],
    "parameter_constraints": {},
    "expires_at": NOW + 86_400, "review_by": NOW + 3_600,
}
DOCUMENT = {"version": 7, "enabled": True, "rules": [CODE_RULE, PUSH_RULE, DEPLOY_RULE]}

GLOBAL_RULE = {
    "rule_id": "rule-global-simulation", "version": 1,
    "human_gate_classes": sorted(HUMAN_GATE_CLASSES),
    "requesters": ["agent-code-1"], "nodes": ["node-example-1"],
    "expires_at": NOW + 86_400, "review_by": NOW + 3_600,
}
GLOBAL_DOCUMENT = {"version": 7, "enabled": True, "rules": [], "global_simulation_rule": GLOBAL_RULE}

# The catalogue is the only classification authority. Names are deliberately
# adversarial: harmless-looking code/deploy names carry human metadata, and
# automatic entries carry name tokens that a token matcher would overexclude.
CATALOGUE = {"actions": {
    "home.display.power_off": {"risk": "R2", "effect": "external_write", "approval": "separate_confirmation", "gate_class": "automatic"},
    "code.edit_file": {"risk": "R1", "effect": "write", "approval": "separate_confirmation", "gate_class": "automatic"},
    "home.reporting.summarize": {"risk": "R1", "effect": "external_write", "approval": "separate_confirmation", "gate_class": "automatic"},
    "deploy.internal.release": {"risk": "R2", "effect": "external_write", "approval": "separate_confirmation", "gate_class": "automatic"},
    "finance.balance.read": {"risk": "R1", "effect": "read", "approval": "none", "gate_class": "automatic"},
    "purchase.place_order": {"risk": "R3", "effect": "external_write", "approval": "separate_confirmation", "gate_class": "human_spending"},
    "communication.send": {"risk": "R3", "effect": "external_write", "approval": "separate_confirmation", "gate_class": "human_communication"},
    "code.sync_review": {"risk": "R2", "effect": "external_write", "approval": "separate_confirmation", "gate_class": "human_communication"},
    "deploy.release_notes": {"risk": "R2", "effect": "external_write", "approval": "separate_confirmation", "gate_class": "human_spending"},
    "system.shell.execute": {"risk": "R4", "effect": "prohibited", "approval": "prohibited", "gate_class": "prohibited"},
    "legacy.unclassified.action": {"risk": "R1", "effect": "write", "approval": "separate_confirmation"},
}}


def request_snapshot(**overrides):
    request = {
        "request_id": "req_code_1", "request_hash": HASH, "action": "code.edit_file",
        "requester": "agent-code-1", "state": "waiting_for_approval",
        "policy_control": "ask", "minimum_control": "policy", "effective_control": "ask",
        "trusted_context": {"node": "node-example-1", "surface": "http", "authenticated_principal": "agent-code-1"},
        "parameters": {"repository": "example-org/example-service", "ref": "refs/heads/main", "summary": "Apply reviewed patch"},
        "approval_challenge": {"request_id": "req_code_1", "request_hash": HASH, "approval_gate_id": "approval", "expires_at": NOW + 300},
        "gates": [{"id": "approval", "kind": "approval", "status": "waiting", "evidence": {"ttl_seconds": 600}}],
    }
    request.update(overrides)
    return request


def parameters(**overrides):
    values = dict(request_snapshot()["parameters"])
    values.update(overrides)
    return {key: value for key, value in values.items() if value is not None}


class AutoApprovalMatcherTests(unittest.TestCase):
    def setUp(self):
        self.policy = AutoApprovalPolicy(DOCUMENT)

    def decide(self, request=None, **kwargs):
        options = {"policy": self.policy, "now": NOW, "policy_version": 7}
        options.update(kwargs)
        return evaluate(request if request is not None else request_snapshot(), **options)

    # --- accept exactly one typed safe member action inside declared scope -------------
    def test_declared_typed_code_work_inside_declared_scope_is_auto_approved(self):
        decision = self.decide()
        self.assertTrue(decision["matched"])
        self.assertEqual("matched_declared_scope", decision["reason_code"])
        self.assertEqual("rule-code-work", decision["rule_id"])
        self.assertEqual(4, decision["rule_version"])
        self.assertEqual("code_edit", decision["action_class"])
        self.assertEqual("example-org/example-service", decision["scope"]["repository"])
        self.assertEqual("refs/heads/main", decision["scope"]["ref"])
        self.assertIsNone(decision["scope"]["commit"])
        self.assertIn("declared", decision["reason"])

    def test_normal_non_force_push_and_declared_staging_deploy_match_their_own_rules(self):
        push = self.decide(request_snapshot(
            action="git.push", request_id="req_push_1",
            parameters=parameters(ref="refs/heads/feature/safe-work", summary=None, commit=COMMIT, force=False),
            approval_challenge={"request_id": "req_push_1", "request_hash": HASH, "approval_gate_id": "approval", "expires_at": NOW + 300}))
        self.assertTrue(push["matched"])
        self.assertEqual("rule-normal-push", push["rule_id"])
        self.assertEqual(COMMIT, push["scope"]["commit"])
        deploy = self.decide(request_snapshot(
            action="deploy.release", request_id="req_deploy_1",
            parameters=parameters(summary=None, commit=COMMIT, environment="staging", target="staging-cluster"),
            approval_challenge={"request_id": "req_deploy_1", "request_hash": HASH, "approval_gate_id": "approval", "expires_at": NOW + 300}))
        self.assertTrue(deploy["matched"])
        self.assertEqual("rule-staging-deploy", deploy["rule_id"])
        self.assertEqual(("staging", "staging-cluster"), (deploy["scope"]["environment"], deploy["scope"]["target"]))

    # --- evidence and audit are single-request, bound, and never execution -------------
    def test_match_emits_single_request_evidence_bound_to_rule_and_exact_request(self):
        request = request_snapshot(parameters=parameters(commit=COMMIT))
        decision = self.decide(request)
        evidence = approval_evidence(decision, request)
        self.assertEqual("approve", evidence["decision"])
        self.assertEqual("req_code_1", evidence["request_id"])
        self.assertEqual(HASH, evidence["request_hash"])
        self.assertEqual("approval", evidence["approval_gate_id"])
        self.assertEqual("ask", evidence["assurance"])
        self.assertEqual(NOW + 300, evidence["expires_at"])
        self.assertIs(False, evidence["authorizes_execution"])
        self.assertEqual(
            {"rule_id": "rule-code-work", "rule_version": 4, "policy_version": 7, "action_class": "code_edit",
             "repository": "example-org/example-service", "ref": "refs/heads/main", "commit": COMMIT,
             "environment": None, "target": None, "reason_code": "matched_declared_scope"},
            evidence["auto_approval"],
        )
        self.assertTrue(evidence["evidence_id"].startswith("auto_"))
        self.assertEqual(evidence["evidence_id"], approval_evidence(decision, request)["evidence_id"])
        other = approval_evidence(self.decide(request_snapshot(
            request_id="req_code_2", parameters=parameters(commit=COMMIT),
            approval_challenge={"request_id": "req_code_2", "request_hash": HASH, "approval_gate_id": "approval", "expires_at": NOW + 300})),
            request_snapshot(request_id="req_code_2"))
        self.assertNotEqual(evidence["evidence_id"], other["evidence_id"])
        audit = audit_metadata(decision, request)
        self.assertEqual(
            {"auto_approved": True, "rule_id": "rule-code-work", "rule_version": 4, "policy_version": 7,
             "request_id": "req_code_1", "request_hash": HASH, "commit": COMMIT,
             "action_class": "code_edit", "reason_code": "matched_declared_scope", "authorizes_execution": False},
            audit,
        )

    def test_evidence_is_invalidated_when_the_commit_changes_after_the_match(self):
        request = request_snapshot(parameters=parameters(commit=COMMIT))
        evidence = approval_evidence(self.decide(request), request)
        self.assertTrue(commit_binding_valid(evidence, commit=COMMIT))
        self.assertFalse(commit_binding_valid(evidence, commit="b" * 40))
        self.assertFalse(commit_binding_valid(evidence, commit=None))
        self.assertFalse(commit_binding_valid(evidence, commit=COMMIT.upper()))

    def test_no_match_never_emits_evidence(self):
        decision = self.decide(request_snapshot(action="terminal.run"))
        self.assertFalse(decision["matched"])
        self.assertIsNone(decision["evidence_binding"])
        with self.assertRaises(ValueError):
            approval_evidence(decision, request_snapshot())

    # --- adversarial rejections --------------------------------------------------------
    def test_undeclared_actions_are_never_auto_approved_by_scoped_rules(self):
        for action in ("terminal.run", "shell.exec", "command.invoke", "code.edit_file.terminal", "git.push_force"):
            with self.subTest(action=action):
                decision = self.decide(request_snapshot(action=action))
                self.assertFalse(decision["matched"])
                self.assertEqual("no_rule_for_action", decision["reason_code"])

    def test_command_path_secret_spending_and_communication_parameters_fail_closed(self):
        cases = {
            "command_parameter_forbidden": {"command": "rm -rf /"},
            "parameter_looks_like_secret": {"api_key": "example-token-value-never-project"},
            "spending_requires_human": {"amount": 100},
            "communication_requires_human": {"recipient": "supplier@example.test"},
            "parameter_not_constrained": {"note": "undeclared free text"},
        }
        for reason_code, extra in cases.items():
            with self.subTest(reason_code=reason_code):
                decision = self.decide(request_snapshot(parameters={**parameters(), **extra}))
                self.assertFalse(decision["matched"])
                self.assertEqual(reason_code, decision["reason_code"])
                for value in extra.values():
                    self.assertNotIn(str(value), decision["reason"])
        constrained = self.decide(request_snapshot(parameters=parameters(summary="Apply an unreviewed patch")))
        self.assertEqual("parameter_value_not_allowed", constrained["reason_code"])

    def test_path_parameters_require_a_host_resolver_and_reject_escapes(self):
        request = request_snapshot(parameters=parameters(path="src/module.py"))
        self.assertEqual("path_parameter_unsafe", self.decide(request)["reason_code"])
        inside = self.decide(request, path_resolver=lambda value: True)
        self.assertEqual("parameter_not_constrained", inside["reason_code"])
        for unsafe in ("/etc/passwd", "../../etc/passwd", "src/../../etc/passwd", "~/notes.txt", "src/./module.py", "src\\module.py"):
            with self.subTest(unsafe=unsafe):
                decision = self.decide(request_snapshot(parameters=parameters(path=unsafe)), path_resolver=lambda value: True)
                self.assertEqual("path_parameter_unsafe", decision["reason_code"])
                self.assertNotIn(unsafe, decision["reason"])
        escaping = self.decide(request_snapshot(parameters=parameters(path="src/module.py")), path_resolver=lambda value: False)
        self.assertEqual("path_parameter_unsafe", escaping["reason_code"])

    def test_near_match_noncanonical_and_traversal_repositories_fail_closed(self):
        for repository, reason_code in (
            ("example-org/example-service2", "repository_not_declared"),
            ("example-org/example-service-staging", "repository_not_declared"),
            ("other-org/example-service", "repository_not_declared"),
            ("Example-Org/Example-Service", "repository_not_canonical"),
            ("example-org/example-service.git", "repository_not_canonical"),
            ("../example-org/example-service", "repository_not_canonical"),
            ("example-org/../example-service", "repository_not_canonical"),
            ("https://example.test/example-org/example-service", "repository_not_canonical"),
            ("example-org/example-service/", "repository_not_canonical"),
            (" example-org/example-service", "repository_not_canonical"),
            ("example-org/example-service\n", "repository_not_canonical"),
            ("*", "repository_not_canonical"),
            ("", "repository_not_canonical"),
            (None, "repository_not_canonical"),
        ):
            with self.subTest(repository=repository):
                decision = self.decide(request_snapshot(parameters=parameters(repository=repository)))
                self.assertFalse(decision["matched"])
                self.assertEqual(reason_code, decision["reason_code"])

    def test_ref_target_environment_requester_node_and_commit_mismatches_fail_closed(self):
        checks = (
            ("ref_not_declared", request_snapshot(parameters=parameters(ref="refs/heads/other"))),
            ("ref_not_canonical", request_snapshot(parameters=parameters(ref="refs/heads/*"))),
            ("ref_not_canonical", request_snapshot(parameters=parameters(ref="refs/heads/../main"))),
            ("ref_not_canonical", request_snapshot(parameters=parameters(ref="main"))),
            ("requester_not_declared", request_snapshot(requester="agent-other")),
            ("node_not_declared", request_snapshot(trusted_context={"node": "node-other"})),
            ("node_not_declared", request_snapshot(trusted_context={})),
        )
        for reason_code, request in checks:
            with self.subTest(reason_code=reason_code, action=request["action"]):
                decision = self.decide(request)
                self.assertFalse(decision["matched"])
                self.assertEqual(reason_code, decision["reason_code"])

    def test_deploy_outside_declared_targets_and_production_need_humans(self):
        def deploy(**extra):
            values = {"summary": None, "commit": COMMIT, "environment": "staging", "target": "staging-cluster", **extra}
            return request_snapshot(action="deploy.release", request_id="req_deploy_1", parameters=parameters(**values),
                                    approval_challenge={"request_id": "req_deploy_1", "request_hash": HASH, "approval_gate_id": "approval", "expires_at": NOW + 300})
        self.assertEqual("target_not_declared", self.decide(deploy(target="other-cluster"))["reason_code"])
        self.assertEqual("environment_not_declared", self.decide(deploy(environment="qa"))["reason_code"])
        self.assertEqual("production_requires_step_up", self.decide(deploy(environment="production"))["reason_code"])
        self.assertEqual("production_requires_step_up", self.decide(deploy(environment="prod"))["reason_code"])
        self.assertEqual("commit_identity_invalid", self.decide(deploy(commit="not-a-commit"))["reason_code"])
        self.assertEqual("commit_identity_invalid", self.decide(deploy(commit=None))["reason_code"])

    def test_destructive_git_force_and_history_rewrite_need_humans(self):
        push = request_snapshot(action="git.push", request_id="req_push_1",
                                parameters=parameters(ref="refs/heads/feature/safe-work", summary=None, commit=COMMIT, force=True),
                                approval_challenge={"request_id": "req_push_1", "request_hash": HASH, "approval_gate_id": "approval", "expires_at": NOW + 300})
        self.assertEqual("destructive_git_requires_human", self.decide(push)["reason_code"])
        for action in ("git.rewrite_history", "git.delete_repository", "git.reset_hard", "git.force_push"):
            with self.subTest(action=action):
                self.assertEqual("no_rule_for_action", self.decide(request_snapshot(action=action))["reason_code"])

    def test_disabled_paused_expired_stale_and_step_up_requests_are_not_auto_approved(self):
        self.assertEqual("auto_approval_paused", self.decide(paused=True)["reason_code"])
        self.assertEqual("rule_disabled", self.decide(disabled_rules=("rule-code-work",))["reason_code"])
        self.assertEqual("auto_approval_disabled", evaluate(request_snapshot(), policy=AutoApprovalPolicy({**DOCUMENT, "enabled": False}), now=NOW)["reason_code"])
        def later(offset):
            return request_snapshot(approval_challenge={"request_id": "req_code_1", "request_hash": HASH, "approval_gate_id": "approval", "expires_at": NOW + offset + 300})
        self.assertEqual("rule_expired", self.decide(later(90_000), now=NOW + 90_000)["reason_code"])
        self.assertEqual("rule_review_overdue", self.decide(later(4_000), now=NOW + 4_000)["reason_code"])
        self.assertEqual("policy_version_stale", self.decide(policy_version=6)["reason_code"])
        self.assertEqual("step_up_requires_independent_transport", self.decide(request_snapshot(effective_control="step_up"))["reason_code"])
        self.assertEqual("request_not_waiting", self.decide(request_snapshot(state="simulated"))["reason_code"])
        self.assertEqual("challenge_unavailable", self.decide(request_snapshot(approval_challenge=None))["reason_code"])

    def test_dry_run_reason_codes_are_a_closed_safe_vocabulary(self):
        decision = self.decide()
        self.assertIn(decision["reason_code"], autoapproval.REASON_CODES)
        self.assertTrue(set(autoapproval.REASON_CODES) >= {"matched_declared_scope", "no_rule_for_action"})
        for code, text in autoapproval.REASON_CODES.items():
            with self.subTest(code=code):
                self.assertRegex(code, r"^[a-z][a-z_]{2,63}$")
                self.assertLessEqual(len(text), 160)
        hostile = self.decide(request_snapshot(parameters={**parameters(), "note": "<script>alert(1)</script>"}))
        self.assertNotIn("<", hostile["reason"])
        self.assertEqual(autoapproval.REASON_CODES[hostile["reason_code"]], hostile["reason"].split(" (")[0])

    # --- policy is host-owned, immutable and not agent-mutable -------------------------
    def test_wildcards_unknown_classes_and_class_confusion_are_rejected_at_load(self):
        for broken in (
            {**CODE_RULE, "repository": "*"},
            {**CODE_RULE, "repository": "example-org/*"},
            {**CODE_RULE, "actions": ["*"]},
            {**CODE_RULE, "actions": ["code.*"]},
            {**CODE_RULE, "actions": ["terminal.run"]},
            {**CODE_RULE, "actions": ["git.push"]},
            {**CODE_RULE, "actions": []},
            {**CODE_RULE, "action_class": "everything"},
            {**CODE_RULE, "refs": ["refs/heads/*"]},
            {**CODE_RULE, "refs": []},
            {**CODE_RULE, "requesters": []},
            {**CODE_RULE, "nodes": []},
            {**CODE_RULE, "version": "4"},
            {**CODE_RULE, "expires_at": None},
            {**CODE_RULE, "parameter_constraints": {"summary": {"pattern": ".*"}}},
            {**CODE_RULE, "parameter_constraints": {"command": {"enum": ["ls"]}}},
            {**DEPLOY_RULE, "environments": ["production"]},
            {**DEPLOY_RULE, "targets": []},
            {key: value for key, value in CODE_RULE.items() if key != "review_by"},
            {**CODE_RULE, "unexpected": True},
        ):
            with self.subTest(rule=sorted(broken.items())[0]):
                with self.assertRaises(AutoApprovalPolicyError):
                    AutoApprovalPolicy({"version": 7, "enabled": True, "rules": [broken]})
        with self.assertRaises(AutoApprovalPolicyError):
            AutoApprovalPolicy({"version": 7, "enabled": True, "rules": [CODE_RULE, CODE_RULE]})

    def test_policy_is_immutable_and_exposes_no_agent_callable_mutation(self):
        with self.assertRaises(TypeError):
            self.policy.rules[0]["version"] = 9
        with self.assertRaises(AttributeError):
            self.policy.rules[0]["actions"].append("terminal.run")
        with self.assertRaises(AttributeError):
            self.policy.enabled = False
        self.assertEqual(4, self.policy.rule("rule-code-work")["version"])
        self.assertIsNone(self.policy.rule("rule-unknown"))
        mutators = [name for name in dir(autoapproval) if not name.startswith("_")
                    and any(verb in name.casefold() for verb in ("create", "add", "update", "delete", "enable", "disable", "set_", "write", "save"))]
        self.assertEqual([], mutators)


class GlobalStandingRuleTests(unittest.TestCase):
    """The standing rule auto-approves every catalogued non-prohibited action for
    simulation, except the two human gate classes declared by catalogue metadata."""

    def setUp(self):
        self.policy = AutoApprovalPolicy(GLOBAL_DOCUMENT)

    def decide(self, action="home.display.power_off", **kwargs):
        options = {"policy": self.policy, "now": NOW, "policy_version": 7, "catalogue": CATALOGUE, "execution_enabled": False}
        options.update(kwargs)
        request = options.pop("request", None) or request_snapshot(
            action=action, parameters={"summary": "Simulate the catalogued action", "target": "example-target", "details": {}})
        return evaluate(request, **options)

    def test_every_catalogued_automatic_action_is_auto_approved_for_simulation(self):
        for action in ("home.display.power_off", "code.edit_file", "home.reporting.summarize"):
            with self.subTest(action=action):
                decision = self.decide(action)
                self.assertTrue(decision["matched"], decision["reason"])
                self.assertEqual("matched_global_simulation_scope", decision["reason_code"])
                self.assertEqual("rule-global-simulation", decision["rule_id"])
                self.assertEqual("global_simulation", decision["action_class"])
                self.assertIn("simulation", decision["reason"])
                request = request_snapshot(action=action, parameters={"summary": "Simulate the catalogued action", "target": "example-target", "details": {}})
                evidence = approval_evidence(decision, request)
                self.assertIs(False, evidence["authorizes_execution"])
                self.assertEqual("policy:auto-approval:rule-global-simulation", evidence["actor"])
                self.assertEqual(HASH, evidence["request_hash"])
                self.assertIs(False, audit_metadata(decision, request)["authorizes_execution"])

    def test_internal_deploy_and_read_only_balance_are_not_overexcluded(self):
        # A token matcher would overexclude these names; metadata says automatic.
        for action in ("deploy.internal.release", "finance.balance.read"):
            with self.subTest(action=action):
                decision = self.decide(action)
                self.assertTrue(decision["matched"], decision["reason"])
                self.assertEqual("matched_global_simulation_scope", decision["reason_code"])

    def test_communication_and_spending_metadata_always_keep_the_human_gate(self):
        for action, reason_code, declared in (
            ("communication.send", "communication_requires_human", "human_communication"),
            ("purchase.place_order", "spending_requires_human", "human_spending"),
        ):
            with self.subTest(action=action):
                decision = self.decide(action)
                self.assertFalse(decision["matched"])
                self.assertEqual(reason_code, decision["reason_code"])
                self.assertIn(declared, decision["reason"])

    def test_harmless_code_and_deploy_names_cannot_smuggle_send_or_payment_metadata(self):
        # Classification is metadata-only: a benign-looking name never removes the
        # human gate its catalogue entry declares.
        self.assertEqual("communication_requires_human", self.decide("code.sync_review")["reason_code"])
        self.assertEqual("spending_requires_human", self.decide("deploy.release_notes")["reason_code"])

    def test_caller_parameters_cannot_remove_communication_or_spending_classification(self):
        for action, reason_code in (("communication.send", "communication_requires_human"),
                                    ("purchase.place_order", "spending_requires_human")):
            for tricky in ({}, {"summary": "internal only", "dry_run": True},
                           {"summary": "no-op", "details": {"internal": True, "amount": 0}}):
                with self.subTest(action=action, tricky=tricky):
                    request = request_snapshot(action=action, parameters=dict(tricky))
                    decision = self.decide(request=request)
                    self.assertFalse(decision["matched"])
                    self.assertEqual(reason_code, decision["reason_code"])

    def test_prohibited_uncatalogued_and_unclassified_actions_stay_closed(self):
        self.assertEqual("action_prohibited_by_catalogue", self.decide("system.shell.execute")["reason_code"])
        self.assertEqual("action_not_catalogued", self.decide("home.unlisted.action")["reason_code"])
        self.assertEqual("gate_class_undeclared", self.decide("legacy.unclassified.action")["reason_code"])
        self.assertEqual("action_not_catalogued", self.decide("code.edit_file", catalogue=None)["reason_code"])
        self.assertEqual("action_not_catalogued", self.decide("code.edit_file", catalogue={"actions": []})["reason_code"])

    def test_execution_mode_pause_disable_identity_and_step_up_are_hard_stops(self):
        self.assertEqual("global_rule_requires_simulation_only", self.decide("code.edit_file", execution_enabled=True)["reason_code"])
        self.assertEqual("global_rule_requires_simulation_only", self.decide("code.edit_file", execution_enabled=None)["reason_code"])
        self.assertEqual("auto_approval_paused", self.decide("code.edit_file", paused=True)["reason_code"])
        self.assertEqual("rule_disabled", self.decide("code.edit_file", disabled_rules=("rule-global-simulation",))["reason_code"])
        self.assertEqual("requester_not_declared", self.decide(request=request_snapshot(action="code.edit_file", requester="agent-other", parameters={}))["reason_code"])
        self.assertEqual("node_not_declared", self.decide(request=request_snapshot(action="code.edit_file", trusted_context={}, parameters={}))["reason_code"])
        self.assertEqual("step_up_requires_independent_transport", self.decide(request=request_snapshot(action="code.edit_file", effective_control="step_up", parameters={}))["reason_code"])

    def test_sensitive_parameters_stay_human_even_under_the_global_rule(self):
        cases = (
            ("parameter_looks_like_secret", {"api_key": "example-token-value-never-project"}),
            ("parameter_looks_like_secret", {"details": {"nested": {"password": "example-secret"}}}),
            ("command_parameter_forbidden", {"command": "rm -rf /"}),
            ("spending_requires_human", {"amount": 10}),
            ("communication_requires_human", {"recipient": "supplier@example.test"}),
            ("destructive_git_requires_human", {"force": True}),
        )
        for reason_code, extra in cases:
            with self.subTest(reason_code=reason_code, extra=sorted(extra)):
                request = request_snapshot(action="code.edit_file", parameters={"summary": "Simulate", **extra})
                decision = self.decide(request=request)
                self.assertFalse(decision["matched"])
                self.assertEqual(reason_code, decision["reason_code"])
        allowed = self.decide(request=request_snapshot(action="code.edit_file", parameters={"summary": "Any free text is fine in simulation", "details": {"note": "no constraint needed"}}))
        self.assertTrue(allowed["matched"], allowed["reason"])

    def test_secret_screening_recurses_through_mappings_and_sequences_at_any_depth(self):
        cases = (
            ("parameter_looks_like_secret", {"details": {"a": {"b": {"c": {"d": {"password": "deep"}}}}}}),
            ("parameter_looks_like_secret", {"details": {"layers": [{"steps": [{"api_key": "nested-in-lists"}]}]}}),
            ("parameter_looks_like_secret", {"details": [[["sk-example-secret-material"]]]}),
            ("parameter_looks_like_secret", {"details": {"a": [{"b": ["Bearer example-value"]}]}}),
            ("command_parameter_forbidden", {"details": {"a": {"b": {"c": {"d": [{"command": "rm -rf /"}]}}}}}),
            ("spending_requires_human", {"details": [{"payment": {"kind": "card"}}]}),
            ("communication_requires_human", {"details": {"drafts": [{"recipient": "person@example.test"}]}}),
            ("destructive_git_requires_human", {"details": {"a": [{"force": True}]}}),
        )
        for reason_code, extra in cases:
            with self.subTest(reason_code=reason_code):
                request = request_snapshot(action="code.edit_file", parameters={"summary": "Simulate", **extra})
                decision = self.decide(request=request)
                self.assertFalse(decision["matched"])
                self.assertEqual(reason_code, decision["reason_code"])
        deep_clean = {"summary": "Simulate", "details": {"a": [{"b": [{"c": {"d": ["harmless", 7, True]}}]}]}}
        allowed = self.decide(request=request_snapshot(action="code.edit_file", parameters=deep_clean))
        self.assertTrue(allowed["matched"], allowed["reason"])

    def test_the_declared_human_gate_classes_cannot_be_shrunk_extended_or_renamed(self):
        for broken in (
            {**GLOBAL_RULE, "human_gate_classes": ["human_communication"]},
            {**GLOBAL_RULE, "human_gate_classes": []},
            {**GLOBAL_RULE, "human_gate_classes": sorted(HUMAN_GATE_CLASSES) + ["credentials"]},
            {**GLOBAL_RULE, "human_gate_classes": ["automatic", "prohibited"]},
            {**GLOBAL_RULE, "human_gate_classes": "human_communication,human_spending"},
            {**GLOBAL_RULE, "requesters": ["*"]},
            {**GLOBAL_RULE, "nodes": []},
            {**GLOBAL_RULE, "version": "1"},
            {key: value for key, value in GLOBAL_RULE.items() if key != "review_by"},
            {key: value for key, value in GLOBAL_RULE.items() if key != "human_gate_classes"} | {"prohibited_classes": sorted(HUMAN_GATE_CLASSES)},
            {**GLOBAL_RULE, "actions": ["code.edit_file"]},
        ):
            with self.subTest(rule=sorted(broken)[0]):
                with self.assertRaises(AutoApprovalPolicyError):
                    AutoApprovalPolicy({**GLOBAL_DOCUMENT, "global_simulation_rule": broken})
        self.assertEqual(("human_communication", "human_spending"), HUMAN_GATE_CLASSES)
        self.assertEqual("rule-global-simulation", self.policy.global_simulation_rule["rule_id"])
        self.assertEqual(tuple(sorted(HUMAN_GATE_CLASSES)), self.policy.global_simulation_rule["human_gate_classes"])
        with self.assertRaises(TypeError):
            self.policy.global_simulation_rule["version"] = 2

    def test_classification_is_metadata_only_with_no_token_vocabulary_left(self):
        self.assertFalse(hasattr(autoapproval, "PROHIBITED_CLASSES"))
        self.assertFalse(hasattr(autoapproval, "FORBIDDEN_ACTION_TOKENS"))
        self.assertFalse(hasattr(autoapproval, "prohibited_class"))


if __name__ == "__main__":
    unittest.main()
