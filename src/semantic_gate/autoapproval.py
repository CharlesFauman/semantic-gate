#!/usr/bin/env python3
"""Policy-owned, default-deny auto-approval for typed safe code-work actions.

The matcher is a pure deterministic function over one exact request. It can only
approve a request whose exact semantic action is a declared member of a typed safe
class inside a checked-in rule that also pins the canonical repository identity,
allowed refs, declared deploy target/environment, host-authenticated requester and
node, closed parameter constraints, commit identity and an unexpired review window.

Everything else keeps the ordinary human gate. Auto-approval is approval evidence
for one request only; it never authorizes execution, never widens policy and is not
reachable from any agent-callable surface. Rules are host-owned and immutable here:
the human control plane may only pause or disable them.
"""
from __future__ import annotations

import hashlib
import os
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping

# Typed safe code-work classes. A rule may only declare members of one class.
SAFE_ACTION_CLASSES: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "code_edit": ("code.edit_file", "code.apply_patch", "code.format_file"),
    "code_test": ("code.run_tests", "code.run_lint"),
    "code_build": ("code.build", "code.typecheck"),
    "git_branch": ("git.create_branch", "git.switch_branch"),
    "git_commit": ("git.commit",),
    "git_push": ("git.push",),
    "git_pull_request": ("git.open_pull_request", "git.update_pull_request"),
    "deploy": ("deploy.release",),
})
COMMIT_REQUIRED_CLASSES = frozenset({"git_push", "git_pull_request", "deploy"})
DEPLOY_CLASSES = frozenset({"deploy"})

RULE_FIELDS = frozenset({
    "rule_id", "version", "action_class", "actions", "repository", "refs", "requesters",
    "nodes", "environments", "targets", "parameter_constraints", "expires_at", "review_by",
})
CORE_PARAMETERS = frozenset({"repository", "ref", "commit", "environment", "target"})

# Hard stop: arbitrary command execution is never auto-approvable, whatever a rule says.
FORBIDDEN_ACTION_TOKENS = (
    "terminal", "shell", "command", "commands", "cmd", "exec", "execute", "eval",
    "script", "sudo", "powershell", "bash", "zsh",
)

# The explicit safety floor. A checked-in document must declare it in full and cannot
# shrink it. These classes keep the ordinary human gate even under a standing rule, and
# they are the classes that must stay human when execution is later enabled.
PROHIBITED_CLASSES: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "credentials": ("secret", "secrets", "credential", "credentials", "password", "passwords",
                    "token", "tokens", "apikey", "keyring", "vault", "rotate", "unseal"),
    "spending": ("purchase", "purchases", "payment", "pay", "order", "orders", "invoice",
                 "billing", "checkout", "transfer", "refund", "subscribe", "spend"),
    "external_communication": ("communication", "communications", "email", "mail", "message",
                               "messages", "sms", "call", "notify", "publish", "post", "broadcast",
                               "share", "tweet", "send"),
    "destructive_git": ("force", "rewrite", "amend", "delete", "destroy", "purge", "prune",
                        "reset", "squash", "rebase", "drop"),
    "undeclared_infrastructure": ("infra", "infrastructure", "deploy", "release", "rollout",
                                  "provision", "terraform", "firewall", "iam", "dns", "cluster",
                                  "scale", "restart", "migrate", "network"),
    "arbitrary_command": FORBIDDEN_ACTION_TOKENS,
})
GLOBAL_RULE_FIELDS = frozenset({
    "rule_id", "version", "prohibited_classes", "requesters", "nodes", "expires_at", "review_by",
})
# Classes a scoped rule may never declare. Undeclared infrastructure is excluded because a
# scoped deploy rule is exactly how an infrastructure effect becomes declared.
SCOPED_RULE_FORBIDDEN_CLASSES = frozenset(set(PROHIBITED_CLASSES) - {"undeclared_infrastructure"})
COMMAND_FIELDS = frozenset({"command", "commands", "cmd", "argv", "args", "script", "shell", "entrypoint"})
SECRET_FIELDS = frozenset({"secret", "secrets", "token", "api_key", "apikey", "password", "credential",
                           "credentials", "private_key", "authorization", "auth", "cookie", "session"})
SPENDING_FIELDS = frozenset({"amount", "price", "cost", "currency", "budget", "payment", "invoice", "quantity"})
COMMUNICATION_FIELDS = frozenset({"recipient", "recipients", "body", "message", "subject", "channel", "audience", "attachments"})
DESTRUCTIVE_FIELDS = frozenset({"force", "force_with_lease", "hard", "hard_reset", "rewrite_history", "delete", "prune"})
PATH_FIELDS = frozenset({"path", "paths", "file", "files", "directory", "dir", "cwd", "workspace", "root"})
PRODUCTION_LABELS = frozenset({"production", "prod", "live", "prd"})

_REPOSITORY = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}/[a-z0-9][a-z0-9._-]{0,62}\Z")
_REF = re.compile(r"refs/(heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]{0,126}\Z")
_ACTION = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\Z")
_LABEL = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z|[0-9a-f]{64}\Z")
_SECRET_VALUE = re.compile(r"(?i)(bearer\s|sk-|ghp_|xox[baprs]-|-----begin )")

REASON_CODES: Mapping[str, str] = MappingProxyType({
    "matched_declared_scope": "Matched a declared auto-approval rule scope for this exact request.",
    "auto_approval_disabled": "Auto-approval is disabled in the checked-in policy.",
    "auto_approval_paused": "A human paused auto-approval from the control plane.",
    "policy_version_stale": "The loaded auto-approval policy version is not the expected version.",
    "request_not_waiting": "The request is not waiting for an approval decision.",
    "challenge_unavailable": "No exact unexpired approval challenge is available for this request.",
    "step_up_requires_independent_transport": "Step-up assurance needs an independently authenticated human transport.",
    "action_class_forbidden": "This action is never auto-approvable, whatever a rule declares.",
    "matched_global_simulation_scope": "Matched the standing simulation-only rule; nothing is executed.",
    "global_rule_requires_simulation_only": "The standing rule only applies while execution is disabled.",
    "action_not_catalogued": "The action is not a member of the checked-in action catalogue.",
    "action_prohibited_by_catalogue": "The action catalogue marks this action prohibited.",
    "prohibited_class_requires_human": "The action falls inside the prohibited safety floor.",
    "no_standing_rule": "No standing simulation-only rule is declared.",
    "action_not_recognized": "The semantic action is not a recognizable typed action identifier.",
    "no_rule_for_action": "No declared rule lists this exact semantic action.",
    "rule_disabled": "A human disabled this rule from the control plane.",
    "rule_expired": "The declared rule has passed its expiry.",
    "rule_review_overdue": "The declared rule has passed its human review date.",
    "requester_not_declared": "The authenticated requester is not declared by the rule.",
    "node_not_declared": "The trusted node is missing or not declared by the rule.",
    "repository_not_canonical": "The repository identity is missing or not a canonical owner/name.",
    "repository_not_declared": "The canonical repository is not the exact repository the rule declares.",
    "ref_not_canonical": "The ref is missing or not a canonical full ref name.",
    "ref_not_declared": "The ref is not one of the exact refs the rule declares.",
    "environment_not_declared": "The environment is not one of the exact environments the rule declares.",
    "target_not_declared": "The deploy target is not one of the exact targets the rule declares.",
    "production_requires_step_up": "Production effects always require a separate step-up human authorization.",
    "commit_identity_invalid": "The immutable commit identity is missing or not a full hexadecimal object name.",
    "commit_changed_since_match": "The commit changed after the rule matched, so the evidence is void.",
    "command_parameter_forbidden": "Terminal, shell and arbitrary command parameters are never auto-approved.",
    "parameter_looks_like_secret": "A parameter looks like a credential or secret material.",
    "spending_requires_human": "Spending parameters always require a human decision.",
    "communication_requires_human": "External communication parameters always require a human decision.",
    "path_parameter_unsafe": "A filesystem path parameter is absolute, traversing, non-canonical or uncontained.",
    "parameter_not_constrained": "A parameter is not covered by the closed constraints of the rule.",
    "parameter_value_not_allowed": "A parameter value is outside the closed values the rule declares.",
    "destructive_git_requires_human": "Destructive or irreversible repository operations always require a human.",
})


class AutoApprovalPolicyError(ValueError):
    """A checked-in auto-approval document is malformed, wildcarded or unsafe."""


def _action_tokens(action: str) -> list[str]:
    return re.split(r"[._-]", action.casefold())


def _forbidden_action(action: str) -> bool:
    return any(token in FORBIDDEN_ACTION_TOKENS for token in _action_tokens(action))


def prohibited_class(action: str) -> str | None:
    """Return the safety-floor class this action belongs to, or None."""
    tokens = set(_action_tokens(action))
    for name in sorted(PROHIBITED_CLASSES):
        if tokens & set(PROHIBITED_CLASSES[name]):
            return name
    return None


def _exact_strings(value: Any, *, field: str, rule_id: str, pattern: re.Pattern[str], allow_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise AutoApprovalPolicyError(f"rule {rule_id} field {field} must be a non-empty list of exact values")
    for item in value:
        if not isinstance(item, str) or not pattern.fullmatch(item) or ".." in item:
            raise AutoApprovalPolicyError(f"rule {rule_id} field {field} must contain exact non-wildcard values")
    if len(set(value)) != len(value):
        raise AutoApprovalPolicyError(f"rule {rule_id} field {field} must not repeat values")
    return tuple(value)


def _validated_rule(raw: Any) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != set(RULE_FIELDS):
        raise AutoApprovalPolicyError(f"auto-approval rule fields must be exactly {sorted(RULE_FIELDS)}")
    rule_id = raw["rule_id"]
    if not isinstance(rule_id, str) or not _LABEL.fullmatch(rule_id):
        raise AutoApprovalPolicyError("rule_id must be a bounded lowercase label")
    action_class = raw["action_class"]
    if action_class not in SAFE_ACTION_CLASSES:
        raise AutoApprovalPolicyError(f"rule {rule_id} declares an unknown action class")
    for field in ("version", "expires_at", "review_by"):
        if type(raw[field]) is not int or raw[field] < 0:
            raise AutoApprovalPolicyError(f"rule {rule_id} field {field} must be a non-negative integer")
    actions = _exact_strings(raw["actions"], field="actions", rule_id=rule_id, pattern=_ACTION, allow_empty=False)
    members = SAFE_ACTION_CLASSES[action_class]
    for action in actions:
        if _forbidden_action(action):
            raise AutoApprovalPolicyError(f"rule {rule_id} declares a never-auto-approvable action")
        declared_class = prohibited_class(action)
        if declared_class in SCOPED_RULE_FORBIDDEN_CLASSES:
            raise AutoApprovalPolicyError(f"rule {rule_id} declares an action inside the {declared_class} safety floor")
        if action not in members:
            raise AutoApprovalPolicyError(f"rule {rule_id} declares an action outside class {action_class}")
    repository = raw["repository"]
    if not isinstance(repository, str) or not _canonical_repository(repository):
        raise AutoApprovalPolicyError(f"rule {rule_id} must declare one canonical repository identity")
    refs = _exact_strings(raw["refs"], field="refs", rule_id=rule_id, pattern=_REF, allow_empty=False)
    requesters = _exact_strings(raw["requesters"], field="requesters", rule_id=rule_id, pattern=_IDENTITY, allow_empty=False)
    nodes = _exact_strings(raw["nodes"], field="nodes", rule_id=rule_id, pattern=_IDENTITY, allow_empty=False)
    deploy = action_class in DEPLOY_CLASSES
    environments = _exact_strings(raw["environments"], field="environments", rule_id=rule_id, pattern=_LABEL, allow_empty=not deploy)
    targets = _exact_strings(raw["targets"], field="targets", rule_id=rule_id, pattern=_LABEL, allow_empty=not deploy)
    if deploy and not (environments and targets):
        raise AutoApprovalPolicyError(f"rule {rule_id} must declare exact deploy environments and targets")
    if not deploy and (environments or targets):
        raise AutoApprovalPolicyError(f"rule {rule_id} may not declare deploy scope outside a deploy class")
    if any(environment.casefold() in PRODUCTION_LABELS for environment in environments):
        raise AutoApprovalPolicyError(f"rule {rule_id} may not declare a production environment")
    constraints = raw["parameter_constraints"]
    if not isinstance(constraints, Mapping):
        raise AutoApprovalPolicyError(f"rule {rule_id} parameter_constraints must be an object")
    frozen_constraints = {}
    for field, constraint in constraints.items():
        if not isinstance(field, str) or not _LABEL.fullmatch(field) or field in CORE_PARAMETERS:
            raise AutoApprovalPolicyError(f"rule {rule_id} constrains an invalid parameter name")
        if _sensitive_field(field) is not None:
            raise AutoApprovalPolicyError(f"rule {rule_id} may not constrain the sensitive parameter {field}")
        if not isinstance(constraint, Mapping) or set(constraint) != {"enum"} or not isinstance(constraint["enum"], list) or not constraint["enum"]:
            raise AutoApprovalPolicyError(f"rule {rule_id} parameter {field} must declare a non-empty enum")
        for value in constraint["enum"]:
            if type(value) not in (str, bool, int) or (isinstance(value, str) and (len(value) > 200 or "*" in value)):
                raise AutoApprovalPolicyError(f"rule {rule_id} parameter {field} declares an unsafe value")
        frozen_constraints[field] = MappingProxyType({"enum": tuple(constraint["enum"])})
    return MappingProxyType({
        "rule_id": rule_id, "version": raw["version"], "action_class": action_class, "actions": actions,
        "repository": repository, "refs": refs, "requesters": requesters, "nodes": nodes,
        "environments": environments, "targets": targets,
        "parameter_constraints": MappingProxyType(frozen_constraints),
        "expires_at": raw["expires_at"], "review_by": raw["review_by"],
    })


def _validated_global_rule(raw: Any) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != set(GLOBAL_RULE_FIELDS):
        raise AutoApprovalPolicyError(f"standing rule fields must be exactly {sorted(GLOBAL_RULE_FIELDS)}")
    rule_id = raw["rule_id"]
    if not isinstance(rule_id, str) or not _LABEL.fullmatch(rule_id):
        raise AutoApprovalPolicyError("standing rule_id must be a bounded lowercase label")
    for field in ("version", "expires_at", "review_by"):
        if type(raw[field]) is not int or raw[field] < 0:
            raise AutoApprovalPolicyError(f"standing rule field {field} must be a non-negative integer")
    declared = raw["prohibited_classes"]
    if not isinstance(declared, list) or set(declared) != set(PROHIBITED_CLASSES):
        raise AutoApprovalPolicyError(f"standing rule must declare the whole safety floor {sorted(PROHIBITED_CLASSES)}")
    requesters = _exact_strings(raw["requesters"], field="requesters", rule_id=rule_id, pattern=_IDENTITY, allow_empty=False)
    nodes = _exact_strings(raw["nodes"], field="nodes", rule_id=rule_id, pattern=_IDENTITY, allow_empty=False)
    return MappingProxyType({
        "rule_id": rule_id, "version": raw["version"], "action_class": "global_simulation",
        "prohibited_classes": tuple(sorted(declared)), "requesters": requesters, "nodes": nodes,
        "expires_at": raw["expires_at"], "review_by": raw["review_by"],
    })


class AutoApprovalPolicy:
    """Immutable, host-owned auto-approval document. No mutation API exists."""

    __slots__ = ("_version", "_enabled", "_rules", "_by_id", "_global_rule")

    def __init__(self, document: Any):
        if not isinstance(document, Mapping) or not {"version", "enabled", "rules"} <= set(document) \
                or set(document) - {"version", "enabled", "rules", "global_simulation_rule"}:
            raise AutoApprovalPolicyError("auto-approval document must contain version, enabled, rules and an optional global_simulation_rule")
        if type(document["version"]) is not int or document["version"] < 1:
            raise AutoApprovalPolicyError("auto-approval version must be a positive integer")
        if type(document["enabled"]) is not bool:
            raise AutoApprovalPolicyError("auto-approval enabled must be a boolean")
        if not isinstance(document["rules"], list) or len(document["rules"]) > 64:
            raise AutoApprovalPolicyError("auto-approval rules must be a bounded list")
        rules = tuple(_validated_rule(rule) for rule in document["rules"])
        identifiers = [rule["rule_id"] for rule in rules]
        if len(set(identifiers)) != len(identifiers):
            raise AutoApprovalPolicyError("auto-approval rule identifiers must be unique")
        object.__setattr__(self, "_version", document["version"])
        object.__setattr__(self, "_enabled", document["enabled"])
        object.__setattr__(self, "_rules", rules)
        object.__setattr__(self, "_by_id", MappingProxyType({rule["rule_id"]: rule for rule in rules}))
        standing = document.get("global_simulation_rule")
        object.__setattr__(self, "_global_rule", None if standing is None else _validated_global_rule(standing))

    def __setattr__(self, name: str, value: Any):
        raise AttributeError("auto-approval policy is immutable")

    @property
    def version(self) -> int:
        return self._version

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def rules(self) -> tuple[Mapping[str, Any], ...]:
        return self._rules

    @property
    def global_simulation_rule(self) -> Mapping[str, Any] | None:
        return self._global_rule

    def rule(self, rule_id: str) -> Mapping[str, Any] | None:
        if self._global_rule is not None and self._global_rule["rule_id"] == rule_id:
            return self._global_rule
        return self._by_id.get(rule_id)


def _canonical_repository(value: Any) -> str | None:
    if not isinstance(value, str) or value != value.strip() or not _REPOSITORY.fullmatch(value):
        return None
    if ".." in value or "//" in value or value.endswith(".git"):
        return None
    return value


def _canonical_ref(value: Any) -> str | None:
    if not isinstance(value, str) or value != value.strip() or not _REF.fullmatch(value):
        return None
    if ".." in value or "//" in value or value.endswith("/") or value.endswith(".lock"):
        return None
    return value


def _sensitive_field(field: str) -> str | None:
    lowered = field.casefold()
    if lowered in COMMAND_FIELDS:
        return "command_parameter_forbidden"
    if lowered in SECRET_FIELDS or any(token in lowered for token in ("secret", "token", "password", "credential", "api_key")):
        return "parameter_looks_like_secret"
    if lowered in SPENDING_FIELDS:
        return "spending_requires_human"
    if lowered in COMMUNICATION_FIELDS:
        return "communication_requires_human"
    return None


def _safe_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 200:
        return False
    if value.startswith(("/", "~", "\\")) or "\\" in value or ".." in value or "\x00" in value:
        return False
    if value != value.strip() or value.endswith("/"):
        return False
    return os.path.normpath(value) == value


def _decision(reason_code: str, *, field: str | None = None, label: tuple[str, str] | None = None, **extra) -> dict:
    reason = REASON_CODES[reason_code]
    if field is not None:
        reason = f"{reason} (parameter: {field})"
    elif label is not None:
        reason = f"{reason} ({label[0]}: {label[1]})"
    decision = {
        "matched": reason_code in {"matched_declared_scope", "matched_global_simulation_scope"}, "reason_code": reason_code, "reason": reason,
        "rule_id": None, "rule_version": None, "policy_version": None, "action_class": None,
        "scope": {"repository": None, "ref": None, "environment": None, "target": None, "commit": None},
        "request_id": None, "request_hash": None, "approval_gate_id": None, "expires_at": None,
        "evidence_binding": None,
    }
    decision.update(extra)
    return decision


def _parameter_failure(rule: Mapping[str, Any], parameters: Mapping[str, Any], path_resolver: Callable[[str], bool] | None) -> tuple[str, str] | None:
    """Return (reason_code, field) for the first unsafe parameter in deterministic order."""
    for field in sorted(parameters):
        value = parameters[field]
        if not isinstance(field, str) or not _LABEL.fullmatch(field):
            return "parameter_not_constrained", None
        sensitive = _sensitive_field(field)
        if sensitive is not None:
            return sensitive, field
        if isinstance(value, str) and _SECRET_VALUE.search(value):
            return "parameter_looks_like_secret", field
        if field.casefold() in DESTRUCTIVE_FIELDS and value is not False:
            return "destructive_git_requires_human", field
        if field in CORE_PARAMETERS:
            continue
        if field.casefold() in PATH_FIELDS or (isinstance(value, str) and ("/" in value or "\\" in value)):
            if not _safe_relative_path(value) or path_resolver is None or path_resolver(value) is not True:
                return "path_parameter_unsafe", field
        constraint = rule["parameter_constraints"].get(field)
        if constraint is None:
            return "parameter_not_constrained", field
        if not any(value is allowed or value == allowed for allowed in constraint["enum"]):
            return "parameter_value_not_allowed", field
    return None


def _sensitive_parameter_failure(parameters: Any, *, depth: int = 0) -> tuple[str, str] | None:
    """Scan bounded nested parameters for safety-floor fields only."""
    if depth > 3 or not isinstance(parameters, Mapping):
        return None
    for field in sorted(parameters, key=str):
        if not isinstance(field, str):
            return "parameter_not_constrained", None
        value = parameters[field]
        sensitive = _sensitive_field(field)
        if sensitive is not None:
            return sensitive, field
        if isinstance(value, str) and _SECRET_VALUE.search(value):
            return "parameter_looks_like_secret", field
        if field.casefold() in DESTRUCTIVE_FIELDS and value is not False:
            return "destructive_git_requires_human", field
        nested = _sensitive_parameter_failure(value, depth=depth + 1)
        if nested is not None:
            return nested
    return None


def _global_rule_failure(rule: Mapping[str, Any], request: Mapping[str, Any], *, now: int, node: Any,
                         catalogue: Any, execution_enabled: bool, disabled_rules) -> tuple[str, Any] | None:
    if rule["rule_id"] in set(disabled_rules or ()):
        return "rule_disabled", None
    if rule["expires_at"] <= now:
        return "rule_expired", None
    if rule["review_by"] <= now:
        return "rule_review_overdue", None
    if execution_enabled is not False:
        return "global_rule_requires_simulation_only", None
    if request.get("requester") not in rule["requesters"]:
        return "requester_not_declared", None
    if not isinstance(node, str) or node not in rule["nodes"]:
        return "node_not_declared", None
    action = request["action"]
    actions = catalogue.get("actions") if isinstance(catalogue, Mapping) else None
    entry = actions.get(action) if isinstance(actions, Mapping) else None
    if not isinstance(entry, Mapping):
        return "action_not_catalogued", None
    if entry.get("effect") == "prohibited" or entry.get("approval") == "prohibited":
        return "action_prohibited_by_catalogue", None
    floor = prohibited_class(action)
    if floor is not None:
        return "prohibited_class_requires_human", ("class", floor)
    return _sensitive_parameter_failure(request.get("parameters"))


def _rule_failure(rule: Mapping[str, Any], request: Mapping[str, Any], *, now: int, node: Any, disabled_rules, path_resolver) -> tuple[str, str | None] | None:
    if rule["rule_id"] in set(disabled_rules or ()):
        return "rule_disabled", None
    if rule["expires_at"] <= now:
        return "rule_expired", None
    if rule["review_by"] <= now:
        return "rule_review_overdue", None
    if request.get("requester") not in rule["requesters"]:
        return "requester_not_declared", None
    if not isinstance(node, str) or node not in rule["nodes"]:
        return "node_not_declared", None
    parameters = request.get("parameters")
    if not isinstance(parameters, Mapping):
        return "parameter_not_constrained", None
    repository = _canonical_repository(parameters.get("repository"))
    if repository is None:
        return "repository_not_canonical", None
    if repository != rule["repository"]:
        return "repository_not_declared", None
    ref = _canonical_ref(parameters.get("ref"))
    if ref is None:
        return "ref_not_canonical", None
    if ref not in rule["refs"]:
        return "ref_not_declared", None
    if rule["action_class"] in DEPLOY_CLASSES:
        environment, target = parameters.get("environment"), parameters.get("target")
        if isinstance(environment, str) and environment.casefold() in PRODUCTION_LABELS:
            return "production_requires_step_up", None
        if not isinstance(environment, str) or environment not in rule["environments"]:
            return "environment_not_declared", None
        if not isinstance(target, str) or target not in rule["targets"]:
            return "target_not_declared", None
    if rule["action_class"] in COMMIT_REQUIRED_CLASSES:
        commit = parameters.get("commit")
        if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
            return "commit_identity_invalid", None
    failure = _parameter_failure(rule, parameters, path_resolver)
    if failure is not None:
        return failure
    return None


def evaluate(request: Any, *, policy: AutoApprovalPolicy, now: int, node: str | None = None,
             policy_version: int | None = None, paused: bool = False, disabled_rules=(),
             path_resolver: Callable[[str], bool] | None = None, catalogue: Any = None,
             execution_enabled: bool = False) -> dict:
    """Deterministically decide whether one exact request is auto-approvable.

    `node` is the host-authenticated node identity. It is never taken from an
    agent-visible projection; a caller holding host trusted context may instead
    leave it unset and pass that context inside the request mapping.
    """
    if not isinstance(request, Mapping):
        raise ValueError("request snapshot must be a mapping")
    if node is None:
        trusted = request.get("trusted_context")
        node = trusted.get("node") if isinstance(trusted, Mapping) else None
    if not policy.enabled:
        return _decision("auto_approval_disabled")
    if paused is True:
        return _decision("auto_approval_paused")
    if policy_version is not None and policy_version != policy.version:
        return _decision("policy_version_stale")
    if request.get("state") != "waiting_for_approval":
        return _decision("request_not_waiting")
    challenge = request.get("approval_challenge")
    if not isinstance(challenge, Mapping) or type(challenge.get("expires_at")) is not int or challenge["expires_at"] <= now:
        return _decision("challenge_unavailable")
    if challenge.get("request_id") != request.get("request_id") or challenge.get("request_hash") != request.get("request_hash"):
        return _decision("challenge_unavailable")
    if request.get("effective_control") == "step_up":
        return _decision("step_up_requires_independent_transport")
    action = request.get("action")
    if not isinstance(action, str) or not _ACTION.fullmatch(action):
        return _decision("action_not_recognized")
    if _forbidden_action(action):
        return _decision("action_class_forbidden")
    candidates = [rule for rule in policy.rules if action in rule["actions"]]
    first_failure = None
    for rule in candidates:
        failure = _rule_failure(rule, request, now=now, node=node, disabled_rules=disabled_rules, path_resolver=path_resolver)
        if failure is None:
            parameters = request["parameters"]
            scope = {
                "repository": rule["repository"],
                "ref": parameters.get("ref"),
                "environment": parameters.get("environment") if rule["action_class"] in DEPLOY_CLASSES else None,
                "target": parameters.get("target") if rule["action_class"] in DEPLOY_CLASSES else None,
                "commit": parameters.get("commit") if isinstance(parameters.get("commit"), str) else None,
            }
            binding = {
                "rule_id": rule["rule_id"], "rule_version": rule["version"], "policy_version": policy.version,
                "action_class": rule["action_class"], "repository": scope["repository"], "ref": scope["ref"],
                "commit": scope["commit"], "environment": scope["environment"], "target": scope["target"],
                "reason_code": "matched_declared_scope",
            }
            return _decision(
                "matched_declared_scope", rule_id=rule["rule_id"], rule_version=rule["version"],
                policy_version=policy.version, action_class=rule["action_class"], scope=scope,
                request_id=request["request_id"], request_hash=request["request_hash"],
                approval_gate_id=challenge.get("approval_gate_id"), expires_at=challenge["expires_at"],
                evidence_binding=binding,
            )
        if first_failure is None:
            first_failure = failure
    standing = policy.global_simulation_rule
    if standing is not None:
        failure = _global_rule_failure(standing, request, now=now, node=node, catalogue=catalogue,
                                       execution_enabled=execution_enabled, disabled_rules=disabled_rules)
        if failure is None:
            binding = {
                "rule_id": standing["rule_id"], "rule_version": standing["version"],
                "policy_version": policy.version, "action_class": "global_simulation",
                "repository": None, "ref": None, "commit": None, "environment": None, "target": None,
                "reason_code": "matched_global_simulation_scope",
            }
            return _decision(
                "matched_global_simulation_scope", rule_id=standing["rule_id"], rule_version=standing["version"],
                policy_version=policy.version, action_class="global_simulation",
                request_id=request["request_id"], request_hash=request["request_hash"],
                approval_gate_id=challenge.get("approval_gate_id"), expires_at=challenge["expires_at"],
                evidence_binding=binding,
            )
        if first_failure is None:
            first_failure = failure
    if first_failure is None:
        return _decision("no_rule_for_action" if candidates or policy.rules else "no_standing_rule")
    reason_code, detail = first_failure
    if isinstance(detail, tuple):
        return _decision(reason_code, label=detail)
    return _decision(reason_code, field=detail)


def approval_evidence(decision: Mapping[str, Any], request: Mapping[str, Any]) -> dict:
    """Build single-request approval evidence bound to the rule and exact request."""
    if not isinstance(decision, Mapping) or not decision.get("matched") or decision.get("evidence_binding") is None:
        raise ValueError("auto-approval evidence requires a matched decision")
    if decision["request_id"] != request.get("request_id") or decision["request_hash"] != request.get("request_hash"):
        raise ValueError("auto-approval evidence must bind the exact matched request")
    binding = dict(decision["evidence_binding"])
    fingerprint = hashlib.sha256(
        "\0".join((
            str(binding["rule_id"]), str(binding["rule_version"]), str(binding["policy_version"]),
            str(decision["request_id"]), str(decision["request_hash"]), str(binding["commit"]),
            str(decision["approval_gate_id"]), str(decision["expires_at"]),
        )).encode("utf-8")
    ).hexdigest()[:32]
    return {
        "evidence_id": "auto_" + fingerprint,
        "request_id": decision["request_id"],
        "request_hash": decision["request_hash"],
        "approval_gate_id": decision["approval_gate_id"],
        "actor": "policy:auto-approval:" + str(binding["rule_id"]),
        "decision": "approve",
        "assurance": "ask",
        "expires_at": decision["expires_at"],
        "authorizes_execution": False,
        "auto_approval": binding,
    }


def audit_metadata(decision: Mapping[str, Any], request: Mapping[str, Any]) -> dict:
    """Immutable audit metadata for one auto-approved request."""
    if not isinstance(decision, Mapping) or not decision.get("matched"):
        raise ValueError("auto-approval audit metadata requires a matched decision")
    binding = decision["evidence_binding"]
    return {
        "auto_approved": True,
        "rule_id": binding["rule_id"],
        "rule_version": binding["rule_version"],
        "policy_version": binding["policy_version"],
        "request_id": request["request_id"],
        "request_hash": request["request_hash"],
        "commit": binding["commit"],
        "action_class": binding["action_class"],
        "reason_code": binding["reason_code"],
        "authorizes_execution": False,
    }


def commit_binding_valid(evidence: Mapping[str, Any], *, commit: Any) -> bool:
    """Auto-approval evidence is void once the bound commit identity changes."""
    if not isinstance(evidence, Mapping):
        return False
    binding = evidence.get("auto_approval")
    if not isinstance(binding, Mapping):
        return False
    bound = binding.get("commit")
    if bound is None:
        return commit is None
    if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
        return False
    return bound == commit
