# Semantic Gate: Standalone Implementation Guide

Status: public beta 0.3.0b1 — security-oriented reference design, not production-ready middleware.

This document is intentionally self-contained. It specifies enough behavior, data shape, storage, cryptography, transaction ordering, interfaces, deployment procedure, failure semantics, and acceptance tests to implement Semantic Gate in another language or platform without depending on another document.

The reference beta targets Python 3.9 or newer. Its core uses only the Python standard library; Ed25519 approval and authorization support is optional and requires `cryptography>=42`. An independent implementation may use another language if it preserves the byte-level encodings, state transitions and transaction guarantees below.

Semantic Gate is a permission plane for agent actions. It decides the minimum control required for an exact semantic action, validates evidence, and issues bounded permission. It does not control workflow. In particular, Semantic Gate does not schedule an effect, automatically consume permission, choose sequencing, retry unknown operations, or force an agent to act. The agent remains free to stop, wait, branch, reorder, request cancellation, or later ask a trusted broker to consume an authorization.

The safe initial deployment is:

```json
{
  "mode": "simulation_only",
  "execution_enabled": false
}
```

Do not call a deployment enforced until the agent's direct effect path and downstream credentials have been removed or technically denied.

## 1. Required properties

A conforming implementation MUST provide all of these properties:

1. Actions are named semantically, such as `purchase.place_order`; callers cannot submit raw shell, browser script, GUI coordinates, arbitrary MCP command selection, or unrestricted tool names as an action.
2. Policy owns the minimum control. Caller input can request a stricter floor but cannot weaken policy.
3. Agent-provided context and host-trusted context are separate inputs.
4. Every request is strict JSON and is canonically hashed with its workflow and identity bindings.
5. Request idempotency is durably reserved before callbacks or policy work.
6. Approval and notification evidence are exact-request-bound, expiring, single-use, and accepted only through a host-only boundary; a hardened multi-process implementation durably reserves evidence IDs.
7. Human approval is cryptographically verified against an enrolled public-key roster.
8. Approval issues permission; it does not execute.
9. The signed authorization bearer is stored only by trusted hosts. Public interfaces expose metadata and a non-secret authorization ID, never the bearer or signing key.
10. ID-only consumption is performed by a trusted broker with fixed actions and credentials.
11. The broker validates signature, audience, requester, action, target, parameters, policy hash, expiry, and revocation.
12. The broker atomically reserves at most one execution attempt before rechecking mutable conditions.
13. Expiry, policy and revocation are checked again immediately before dispatch.
14. Any indeterminate post-dispatch result is treated as Unknown and cannot be automatically retried. If persisting unknown also fails, the durable executing reservation remains blocked until operator-confirmed recovery.
15. Requests, authorizations, idempotency, cancellation, receipts, unknown outcomes and reconciliation survive restart.
16. Existing MCP integration is declarative and closed: executable, environment names, server, read tool, action target and effect tool are host configuration, never caller selections.
17. Audit and observation records are bounded and content-free; they exclude prompts, argument bodies, outputs, message text, commands, files, credentials and arbitrary summaries.
18. Enforcing deployment requires bypass removal. A gate beside a raw credential or effectful tool is observation, not enforcement.

## 2. Threat model

### 2.1 Adversaries and failures

Assume an agent or untrusted caller may:

- choose any public API method and repeat, reorder or race calls;
- supply malformed JSON, duplicate idempotency keys, stale evidence, arbitrary labels, fake actor names, unexpected fields or very large bodies;
- try to reduce the requested permission level;
- try to select a downstream executable, MCP server, tool, credential, target or command;
- learn request IDs and authorization IDs;
- retain old policy responses or authorizations;
- crash or disconnect the broker near dispatch;
- race cancellation, bulk revocation and consumption;
- exploit process restart to replay a request or effect;
- make a downstream MCP return malformed JSON, EOF, timeout or a result after performing the effect;
- attempt to use an agent identity as a human approver.

Also assume ordinary system failures: process death, machine reboot, SQLite contention, disk-full after downstream success, network partition during an effect, expired approval while processing, and unavailable revocation service.

### 2.2 Assets

Protect:

- target credentials and private signing keys;
- enrolled human identity and approval integrity;
- current policy and its minimum-control decision;
- exact action, target and parameter binding;
- single-attempt and no-automatic-retry guarantees;
- durable lifecycle truth and reconciliation evidence;
- private request contents and downstream results;
- the distinction between proposal authority and execution authority.

### 2.3 Trust boundaries

Use at least these separate principals/processes:

```text
untrusted agent / caller
        |
        | proposal, status, cancellation by ID
        v
agent-facing API or MCP host
        |
        | host-authenticated principal + host-trusted context
        v
policy engine + request ledger
        ^
        | verified human approval only
human signer -> approval transport / roster

policy engine -> host-only signed authorization store
                         |
                         | authorization ID only
                         v
trusted broker -> fixed recheck -> fixed effect target
                         |
                         v
                  downstream credential
```

The agent-facing process MUST NOT have:

- approval signing or ingestion authority;
- authorization signing keys;
- bearer-token retrieval;
- target registration;
- `ExecutionAuthority` or equivalent dispatch capability;
- downstream effect credentials;
- policy mutation or public-key enrollment authority.

A broker may hold only the verifier it needs. Prefer a public-key authorization verifier in a separate broker process rather than sharing the coordinator's private signing key.

### 2.4 Non-goals

Semantic Gate is not:

- a planner, workflow engine, scheduler or task queue;
- an assurance that an arbitrary downstream system is correct;
- magic exactly-once delivery;
- a transparent arbitrary MCP proxy;
- a sandbox for unrestricted shell, PowerShell, AppleScript, browser JavaScript, GUI coordinates or arbitrary Home Assistant service calls;
- enforcement while callers retain direct credentials or raw effectful tools;
- a substitute for OS, network and credential least privilege;
- a secret vault, notification provider, process/container isolation system, distributed consensus protocol, or formal proof that adapter code is correct;
- proof that a notification reached a human unless the host provides bound delivery evidence;
- production-ready solely because the reference beta tests pass.

## 3. Canonical JSON

All security-sensitive JSON MUST be strict and canonical.

Reject:

- NaN, positive/negative infinity;
- non-string object keys;
- non-JSON values;
- duplicate or unknown fields where a closed schema is specified;
- recursive or overlarge structures according to implementation limits.

Canonical parsing and encoding:

```python
import json

class DuplicateKey(ValueError):
    pass

def reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKey(f"duplicate JSON key: {key}")
        result[key] = value
    return result

def parse_strict_json(text):
    return json.loads(
        text,
        object_pairs_hook=reject_duplicate_pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )

def engine_canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")

def signed_canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")
```

The engine uses `engine_canonical` for request and policy hashes. Approval and authorization HMAC/Ed25519 domains use `signed_canonical` for byte compatibility with `0.3.0b1`. Do not apply Unicode normalization: code-point-distinct input remains distinct. Use Python-compatible finite JSON number rendering for this protocol version; reject integers outside signed 64-bit range before encoding. A future switch to RFC 8785/JCS requires a new protocol version.

Interoperability vector:

```json
{"label":"café","count":1,"active":true}
```

```text
engine bytes: {"active":true,"count":1,"label":"café"}
engine SHA-256: e64a72dbeda41af6626381875993748857e91953f58f2e1fbc4b7350e33057e5
signed bytes: {"active":true,"count":1,"label":"caf\u00e9"}
signed SHA-256: 4c30eade4bfaa720a5195804335841145cfa5972a080d86006e606aac5f65757
```

Apply these reference boundary limits before engine hashing: maximum depth 64, maximum 100,000 JSON nodes, maximum 10,000 members in any object/array, maximum 65,536 characters in a string, signed 64-bit integers, finite floats, and string object keys. HTTP, stdio MCP and downstream MCP messages are capped at 1 MiB. Reject oversized input before parsing or dispatch.

For byte-compatible `0.3.0b1` interoperability, note that the engine request/policy canonicalizer uses `ensure_ascii=False`, while approval and authorization signature canonicalizers use Python's default ASCII escaping. Both use sorted keys, compact separators and UTF-8. Therefore non-ASCII strings can produce different signed bytes across those domains. Do not reuse a canonical byte string from one domain in another. A new implementation may deliberately unify this only as a versioned protocol change.

## 4. Semantic action catalogue and policy

### 4.1 Action catalogue

Create a closed catalogue before policy execution. Each action record should contain:

```json
{
  "action": "purchase.place_order",
  "description": "Place one order through the reviewed order service",
  "privacy_class": "private",
  "default_control": "ask",
  "allowed_principals": ["example-agent"],
  "target": "commerce.place_order"
}
```

Action names SHOULD match:

```text
^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$
```

Catalogue mutation is an administrative operation separate from proposing an action. Callers may list/explain permitted actions but may not define targets.

Track deployment maturity per action, not globally:

```text
catalogued  policy exists, but runtime paths may be untouched
shadowed    decisions/observations run, while a direct bypass still exists
enforced    approved broker path works and the same direct unapproved path is technically denied
```

### 4.2 Control ordering

Use this effective-control ordering for approval-bearing version-2 workflows:

```text
policy < ask < step_up
```

`policy` means “no caller override”; it is not a weaker policy decision. Compute:

```python
rank = {"policy": 0, "ask": 1, "step_up": 2}
approval_levels = [gate["level"] for gate in workflow["gates"] if gate["kind"] == "approval"]
policy_rank = max(2 if level == "human_step_up" else 1 for level in approval_levels)
caller_floor = payload.get("minimum_control", "policy")
requested_rank = policy_rank if caller_floor == "policy" else rank[caller_floor]
effective_rank = max(policy_rank, requested_rank)
policy_control = "step_up" if policy_rank == 2 else "ask"
effective_control = "step_up" if effective_rank == 2 else "ask"
```

Policy owns the minimum control. Reject any caller value outside `policy`, `ask`, `step_up`. Never accept `allow`, `off`, a boolean bypass, a caller-supplied role, or a caller-supplied “already approved” flag as a reduction.

When the effective rank is step-up, rewrite every approval gate to `human_step_up` and cap each approval TTL at 300 seconds. A password-only simulation panel supplies at most ordinary `ask`; genuine step-up requires an independently authenticated stronger human channel.

Approval levels are exactly `human_approve_once` (maps to `ask`) and `human_step_up` (maps to `step_up`). Trusted context may select among different host-authored workflows/catalog actions, but it does not alter this rank algorithm inside one loaded workflow.

### 4.3 Version-2 policy shape

A complete safe starting policy:

```json
{
  "version": 2,
  "mode": "simulation_only",
  "execution_enabled": false,
  "workflows": {
    "purchase.place_order": {
      "description": "Place an order after inventory checks, notification, human step-up approval and immediate recheck.",
      "principals": ["example-agent"],
      "target_tool": "commerce.place_order",
      "parameter_schema": {
        "type": "object",
        "additionalProperties": false,
        "required": ["sku", "quantity", "currency"],
        "properties": {
          "sku": {"type": "string", "minLength": 1},
          "quantity": {"type": "integer", "minimum": 1},
          "currency": {"type": "string", "enum": ["USD", "EUR", "GBP"]}
        }
      },
      "gates": [
        {"id": "schema", "kind": "schema", "requires": []},
        {
          "id": "inventory_before",
          "kind": "tool",
          "requires": ["schema"],
          "tool": "inventory.available",
          "input": {"sku": "$parameters.sku", "quantity": "$parameters.quantity"},
          "expect": {"path": "available", "op": "eq", "value": true},
          "recheck": false
        },
        {
          "id": "notify",
          "kind": "notify",
          "requires": ["inventory_before"],
          "recipient": "human_owner",
          "template": "Review purchase request"
        },
        {
          "id": "approval",
          "kind": "approval",
          "requires": ["notify"],
          "level": "human_step_up",
          "ttl_seconds": 180
        },
        {
          "id": "inventory_after",
          "kind": "tool",
          "requires": ["approval"],
          "tool": "inventory.available",
          "input": {"sku": "$parameters.sku", "quantity": "$parameters.quantity"},
          "expect": {"path": "available", "op": "eq", "value": true},
          "recheck": true
        },
        {
          "id": "execute",
          "kind": "execute",
          "requires": ["inventory_after"],
          "tool": "commerce.place_order",
          "simulation_only": true
        }
      ]
    }
  },
  "authorization": {
    "audience": "orders-broker",
    "ttl_seconds": 300
  }
}
```

### 4.4 Closed policy validation

At load time MUST enforce:

- top-level fields are exactly `version`, `mode`, `execution_enabled`, `workflows`, `authorization` for version 2;
- version is integer 2 (version 1 may exist only as documented compatibility mode);
- mode is `simulation_only` or `enforcing`;
- `execution_enabled` is boolean;
- `simulation_only` plus `execution_enabled=true` is invalid;
- authorization fields are exactly `audience`, `ttl_seconds`; audience is non-empty and TTL positive;
- workflows are a non-empty object;
- each workflow has exactly description, principals, target_tool, parameter_schema, gates;
- principals are unique, non-empty strings; wildcard `*` cannot be mixed with names;
- parameter schemas are closed object schemas with `additionalProperties=false`;
- properties support only string, boolean, integer, number, object and array plus bounded `minLength`, `enum`, `minimum`, `maximum`; nested object/array values require domain validation in adapters;
- gates have exact fields for their kind and unique IDs;
- dependencies reference known gates and form a DAG;
- exactly one execute gate exists and its tool equals `target_tool`;
- approval depends on notification;
- execute has notification and approval ancestors;
- each post-approval tool marked `recheck=true` depends on approval;
- in an execution-enabled policy, every approval ancestor has a later recheck ancestor before execute;
- disabled execution cannot contain a live execute gate.

Gate kinds:

```text
schema     validate exact parameters
condition  compare a request/context/trusted-context path
 tool      invoke only a host-registered read and test its result
notify     obtain bound notification evidence
approval   stop and wait for host-only verified evidence
execute    issue version-2 authorization; do not dispatch target
```

Exact gate field sets are closed:

```text
schema:    id, kind, requires
condition: id, kind, requires, path, op, value
tool:      id, kind, requires, tool, input, expect, recheck
notify:    id, kind, requires, recipient, template
approval:  id, kind, requires, level, ttl_seconds
execute:   id, kind, requires, tool, simulation_only
```

`eq` is type-strict (boolean is not numeric); `in` requires a configured list; `lte`/`gte` require finite numbers; `truthy` means exactly boolean `true`. Tool `input` values beginning with `$` resolve dot paths from the request (`$parameters.sku`, `$context.reason`, `$trusted_context.risk`); literals are copied unchanged. Missing paths fail closed.

Evaluate in deterministic policy-list order: repeatedly scan gates, run a pending gate only when every dependency is satisfied, and stop immediately on waiting, block, failure, authorization, simulation or execution. Independent gates therefore execute in their declared list order.

Comparison operators may be `eq`, `in`, `lte`, `gte`, `truthy`. Tool-input references begin with `$`; the engine strips it and resolves paths such as `$parameters.sku`, `$context.reason`, `$trusted_context.risk`, `$action`, or `$parameters`. Condition-gate `path` does not begin with `$`; use `parameters.sku`, `context.reason`, or `trusted_context.risk`. Dot lookup traverses objects only and missing components fail closed.

## 5. Proposal, identity and request hashing

### 5.1 Agent-facing proposal

Accept exactly:

```json
{
  "action": "purchase.place_order",
  "parameters": {"sku": "example-sku", "quantity": 1, "currency": "USD"},
  "context": {"reason_code": "restock"},
  "idempotency_key": "agent-generated-stable-key",
  "minimum_control": "policy"
}
```

Required fields: `action`, `parameters`, `context`, `idempotency_key`. Optional: `minimum_control`. Reject unknown fields. The authenticated requester and trusted context MUST be injected by the host transport and MUST NOT be accepted from these arguments.

### 5.2 Request fingerprint

Before calling the policy engine, compute the durable request fingerprint:

```python
fingerprint_document = {
    "request": normalized_agent_payload,
    "host_context": trusted_host_context,
}
fingerprint = sha256(canonical(fingerprint_document)).hexdigest()
```

Reserve `(principal, idempotency_key, fingerprint)` durably before callbacks. The key is scoped to principal. Same principal/key plus different fingerprint is a conflict. A crash with status `reserved` MUST fail closed and require operator recovery; it must not repeat backend callbacks.

For `0.3.0b1` compatibility, the engine request hash binds exactly:

```json
{
  "version": 2,
  "action": "purchase.place_order",
  "parameters": {},
  "context": {},
  "trusted_context": {},
  "requester": "example-agent",
  "idempotency_key": "stable-key",
  "minimum_control": "policy",
  "policy_control": "step_up",
  "effective_control": "step_up",
  "workflow": {}
}
```

Hash the canonical encoding with SHA-256. Never trust a caller-supplied hash.

Derive the deterministic request ID as:

```python
from hashlib import sha256

material = f"{requester}:{idempotency_key}:{request_hash}".encode("utf-8")
request_id = "req_" + sha256(material).hexdigest()[:24]
```

The engine also retains a process-local `(requester, idempotency_key)` binding, but it does not replace the durable reservation. If a crash leaves a durable reservation in `reserved`, the beta intentionally fails every replay as “in progress; operator recovery is required.” Version `0.3.0b1` has no generic reserved-request recovery command; operators must preserve the database, investigate whether callbacks ran, and use a deployment-specific audited repair. Treat this as a Beta limitation, not permission to delete the row and retry blindly.

### 5.3 Public request snapshot

A public snapshot can contain:

```json
{
  "request_id": "req_random",
  "request_hash": "64-lowercase-hex",
  "action": "purchase.place_order",
  "requester": "example-agent",
  "parameters": {},
  "context": {},
  "state": "waiting_for_approval",
  "effective_control": "step_up",
  "created_at": 1700000000,
  "updated_at": 1700000000,
  "gates": [],
  "execution_possible": false,
  "consumption_possible": false
}
```

Remove `trusted_context`, authorization bearer tokens, private provenance bodies, signing keys and target credentials before public persistence or response. A hardened deployment also uses the closed receipt projection in section 12.2 so unrestricted downstream outputs never enter requester-visible snapshots. The `0.3.0b1` reference can retain complete gate/receipt result objects; treat that as a documented beta privacy/size gap and keep sensitive adapters simulation-only until a projector is installed.

## 6. Request state machine

Request state machine:

```text
processing
  |-- blocked
  |-- failed
  |-- waiting_for_approval
  |      |-- cancelled
  |      |-- denied
  |      `-- authorized
  |             |-- cancelled
  |             |-- denied
  |             `-- consuming
  |                    |-- simulated
  |                    |-- executed
  |                    |-- failed       (proved pre-dispatch failure)
  |                    `-- outcome_unknown
  |                           |-- executed  (explicit reconciliation)
  |                           `-- failed    (explicit reconciliation)
  `-- expired (only by explicit per-request policy/operator handling)
```

Do not run a global startup sweep that guesses request outcomes. Authorized, consuming and outcome-unknown projections are durable. If a pre-authorization process-local workflow is lost, permit explicit requester cancellation and reproposal; do not silently approve, execute or regenerate it.

The engine loops over pending gates whose dependencies are satisfied. For each gate:

- schema: validate and mark passed;
- condition: resolve path, compare, block on mismatch or unavailable data;
- tool: call only read registry; failure is non-retryable unless a new request is made;
- notify: require bound evidence; in enforcing mode require delivered=true and a sane delivery timestamp;
- approval: set waiting state and return;
- execute v2: validate all approvals are still unexpired, build/sign/store authorization, set authorized, return without target invocation.

Gate status values are `pending`, `passed`, `simulated`, `waiting`, `approved`, `authorized`, `blocked`, and `failed`. Cancellation is allowed only to the original requester. Cancelling an issued authorization must first transition the durable authorization from issued to cancelled; executing and terminal authorizations are not cancellable through the requester API.

## 7. Notification evidence

A notification adapter is host-provided. Its evidence MUST bind:

```json
{
  "notification_id": "unique-event-id",
  "request_id": "req_random",
  "request_hash": "64-hex",
  "notification_gate_id": "notify",
  "recipient": "human_owner",
  "template_hash": "sha256-of-configured-template",
  "delivered": true,
  "delivered_at": 1700000001
}
```

Enforcing mode rejects missing, simulated, stale, misbound or reused notification evidence. Notification delivery does not approve and cannot execute.

The exact reference freshness rule is `request.created_at <= delivered_at <= now`; there is no separate age TTL. Reserve `notification_id` with the unique table in section 10 in the same transaction that projects the gate passed. A duplicate ID, future time, pre-request time, wrong recipient/template/gate/request/hash, or `delivered != true` fails closed in enforcing mode.

Compute `template_hash = SHA256(configured_template.encode("utf-8"))` with no trailing newline or normalization.

## 8. Human approval

### 8.1 Host-only boundary

Approval ingestion MUST NOT be an agent-facing MCP/HTTP method. An admin simulation panel is acceptable only for simulation and must not be represented as cryptographic human assurance. Production approval requires a trusted transport that verifies an enrolled human key.

Caller-supplied actor or signer labels are never trusted approval provenance.

The beta also contains a host-internal HMAC approval envelope used by trusted coordinator code. Its signed fields include request/gate bindings and may carry extra signed fields; unlike the Ed25519 transport below, it is not one universal closed public schema. Keep that internal format host-only. New external human transports should use a closed schema and public-key identity.

### 8.2 Human approval schema

Unsigned human approval schema has exactly these fields:

```json
{
  "evidence_id": "human-event-unique",
  "request_id": "req_random",
  "request_hash": "64-hex",
  "actor": "human:owner",
  "decision": "approve",
  "assurance": "step_up",
  "key_id": "owner-key-2026",
  "signed_at": 1700000010,
  "expires_at": 1700000110
}
```

The signed form adds exactly:

```json
{"signature": "base64-ed25519-signature"}
```

Sign the canonical unsigned object. Verification MUST check:

- exact field set and strict JSON;
- key ID exists in roster;
- enrolled actor exactly equals evidence actor and starts `human:`;
- decision is exactly `approve`;
- assurance is enrolled and ranks at least the request's effective control;
- request ID and request hash exactly match the currently pending request;
- `request.created_at <= signed_at <= now < expires_at`;
- `now - signed_at <= max_age_seconds`;
- Ed25519 signature verifies;
- evidence ID is non-empty, unique and not consumed;
- approval gate is currently waiting;
- approval expiry is within the configured gate TTL.

`max_age_seconds` is a verifier/roster setting with reference default 300 seconds. At bridge ingestion time `now`, require `request.created_at <= signed_at <= now < signed_expires_at` and `now - signed_at <= max_age_seconds`. The internal approval expiry is `min(signed_expires_at, now + approval_gate.ttl_seconds)`. Authorization expiry is then `min(internal_approval_expiries..., authorization_issued_at + policy.authorization.ttl_seconds)`.

The Ed25519 transport is request-bound rather than carrying an `approval_gate_id`. Deterministic evaluation stops at the first waiting approval, so the trusted bridge requires exactly one currently waiting approval gate and inserts that gate ID into the internal host evidence before ingestion. If an implementation permits multiple concurrently waiting approvals, extend and version the signed schema to include `approval_gate_id`; do not guess which gate an approval satisfies.

### 8.3 Ed25519 roster

Ed25519 roster document:

```json
{
  "keys": {
    "owner-key-2026": {
      "actor": "human:owner",
      "public_key": "base64-raw-32-byte-ed25519-public-key",
      "assurances": ["ask", "step_up"]
    }
  }
}
```

Roster mutation is a separate administrative action. The agent cannot enroll keys. Keep private keys outside the coordinator and repository, preferably hardware-backed. A signer accepts an unsigned decision file and private-key path, not private key material in command arguments.

After verification, forward only:

```json
{
  "actor": "human:owner",
  "assurance": "step_up",
  "evidence_id": "human-event-unique",
  "expires_at": 1700000110,
  "provenance": {
    "transport": "ed25519",
    "key_id": "owner-key-2026",
    "signed_at": 1700000010,
    "signature_sha256": "sha256-of-signature-bytes"
  }
}
```

This provenance is bounded and does not store the signature as an audit message body. Multiple approvals MUST produce a deterministic mapping keyed by each evidence ID, never one unkeyed provenance value.

## 9. Deferred authorization

### 9.1 Authorization claims

Authorization claims are closed and contain exactly:

```json
{
  "authorization_id": "auth_random",
  "issuer": "semantic-gate-host",
  "audience": "orders-broker",
  "request_id": "req_random",
  "request_hash": "64-hex",
  "requester": "example-agent",
  "assurance": "step_up",
  "action": "purchase.place_order",
  "target": "commerce.place_order",
  "parameters": {"sku": "example-sku", "quantity": 1, "currency": "USD"},
  "parameters_hash": "sha256-canonical-parameters",
  "policy_hash": "sha256-canonical-normalized-policy",
  "approval_evidence_ids": ["human-event-unique"],
  "approval_provenance": {
    "human-event-unique": {
      "transport": "ed25519",
      "key_id": "owner-key-2026",
      "signed_at": 1700000010,
      "signature_sha256": "64-hex"
    }
  },
  "issued_at": 1700000011,
  "expires_at": 1700000110,
  "nonce": "random-128-bits-or-more",
  "execution_enabled": false,
  "simulation_only": true
}
```

The signed token adds exactly `signature`. Set `expires_at` to the minimum of authorization TTL and every approval expiry. Sort approval evidence IDs. Recompute `parameters_hash`; do not accept it from the caller.

`policy_hash` is SHA-256 of `engine_canonical(load_policy(policy_document))`: the closed, validated base policy exactly as loaded. It does not include per-request step-up rewrites; those are separately bound inside the request hash's effective workflow. For the complete policy JSON in section 4.3, the policy hash is:

```text
a0d5ccda6aa3ad5c5ffacb9637c0549091616f037420f88757ac092e56f4572b
```

The `0.3.0b1` envelope intentionally has no in-band algorithm or key ID. Verifier selection is host configuration, not token input: one issuer/audience is bound to exactly one configured HMAC or Ed25519 verifier. Never choose an algorithm from untrusted token data. Rotate by introducing a versioned issuer (for example `semantic-gate-host-v2`) and explicitly configuring overlapping old/new verifiers until old authorizations expire.

### 9.2 Signing

For a single trusted process, HMAC-SHA-256 with at least 32 random key bytes can sign canonical claims. For separation of duties, prefer Ed25519:

```python
body = canonical(claims)
signature = base64.b64encode(ed25519_private_key.sign(body)).decode("ascii")
token = {**claims, "signature": signature}
```

Brokers receive only the public key and expected issuer. Verify exact token fields, signature, issuer, audience, validity window and parameters hash.

### 9.3 Host-only bearer storage

The signed token is a bearer capability and is host-confined. Host-only bearer storage means:

- store the token only in the trusted authorization database;
- do not return it from agent-facing request/status APIs;
- do not place it in logs, audit metadata, URLs, messages or browser storage;
- administrative listing returns metadata only;
- broker public API accepts an authorization ID, not a token;
- never import a caller-supplied bearer into trusted storage.

The authorization ID is non-secret. Security relies on broker authentication, requester binding, signature, policy, audience, lifecycle state and fixed target—not ID secrecy.

## 10. Durable SQLite model

Use one SQLite database when possible so request and authorization projection share transactions. Required pragmas:

```sql
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=FULL;
PRAGMA busy_timeout=5000;
```

Core schema:

```sql
CREATE TABLE requests (
  request_id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  requester TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  snapshot_json TEXT NOT NULL
);

CREATE TABLE audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT,
  event TEXT NOT NULL,
  actor TEXT NOT NULL,
  at INTEGER NOT NULL,
  metadata_json TEXT NOT NULL
);

CREATE TABLE request_idempotency (
  principal TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  request_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  status TEXT NOT NULL,
  PRIMARY KEY(principal, idempotency_key)
);

CREATE TABLE authorizations (
  authorization_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  state TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  token_json TEXT NOT NULL,
  consumer TEXT,
  receipt_json TEXT,
  request_snapshot_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE controls (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  actor TEXT NOT NULL
);

CREATE TABLE approval_evidence (
  evidence_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  gate_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER NOT NULL,
  provenance_json TEXT NOT NULL
);

CREATE TABLE notification_evidence (
  notification_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  gate_id TEXT NOT NULL,
  consumed_at INTEGER NOT NULL,
  metadata_json TEXT NOT NULL
);

CREATE TABLE effect_uncertainty (
  effect_key TEXT PRIMARY KEY,
  authorization_id TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK(state IN ('executing','unknown')),
  updated_at INTEGER NOT NULL
);

CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
);
```

Bound retained metadata. The reference defaults to at most 100,000 observations and 200,000 audit events, pruned oldest-first after insertion. Request listing is capped at 500 records, and audit reads at 1,000 per call. Choose explicit limits in other implementations rather than permitting unbounded local denial of service.

If content-free observations are implemented:

```sql
CREATE TABLE observations (
  event_id TEXT NOT NULL,
  principal TEXT NOT NULL,
  phase TEXT NOT NULL,
  operation TEXT NOT NULL,
  semantic_class TEXT NOT NULL,
  outcome TEXT NOT NULL,
  occurred_at INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  metadata_json TEXT NOT NULL,
  observation_json TEXT NOT NULL,
  PRIMARY KEY(principal, event_id)
);
```

### 10.1 Idempotency reservation transaction

Before backend callbacks:

```text
BEGIN IMMEDIATE
SELECT fingerprint, request_id, status
  FROM request_idempotency
 WHERE principal=? AND idempotency_key=?

if missing:
  INSERT (..., request_id='', status='reserved')
  COMMIT
  caller owns reservation
elif fingerprint differs:
  ROLLBACK; reject conflict
elif status != 'complete':
  ROLLBACK; reject; operator recovery required
else:
  COMMIT; return existing request_id
```

After backend returns, atomically insert the request snapshot/audit and update the reservation to `complete`. A crash between reservation and completion does not permit automatic callback repetition.

### 10.2 Atomic authorization issuance

Before issuance, a hardened multi-process implementation consumes approval evidence in the same write transaction:

```text
BEGIN IMMEDIATE
INSERT approval_evidence(...)                 -- unique evidence_id; conflict rejects
verify request row is still waiting on the exact gate/hash
update gate snapshot to approved
insert authorization and complete authorized request snapshot
COMMIT
```

Notification evidence is reserved similarly when its gate passes. At the transaction boundary, require IDs/gate/request/actor strings to be non-empty and at most 200 characters; request hashes and signature hashes are lowercase 64-hex; expiry/timestamps are signed-64 integers; provenance is exactly either `{ "transport": "hmac-host" }` or the bounded Ed25519 fields shown in section 8.3; and every encoded metadata/provenance object is at most 8 KiB. Recheck every request/hash/gate/actor/time binding inside the transaction before insertion. The `0.3.0b1` reference engine uses process-local consumed-ID sets and loses pending workflow state on restart, so its request/hash binding still prevents cross-request reuse but it does not provide this durable multi-process uniqueness table. Implement the tables above for hardened conformance.

Construct the complete public `authorized` request snapshot before storing the token. Then:

```text
BEGIN IMMEDIATE
SELECT token_json,state,updated_at FROM authorizations WHERE authorization_id=?
if existing token differs: ROLLBACK; reject
if absent:
  INSERT authorization with token_json and request_snapshot_json
  UPDATE matching requests row to authorized snapshot (if same database)
if existing identical token:
  preserve current lifecycle state, receipt and updated_at
project current authorization state, never regress to issued
COMMIT
```

This closes the crash window in which a consumable authorization exists while the durable request still says `waiting_for_approval`. Retaining `request_snapshot_json` also allows separate-database deployments to repair an orphaned request projection by request ID.

Projection repair MUST use compare-and-swap against the exact stale `snapshot_json`, so an old reader cannot overwrite a concurrent executing/completed/reconciled state.

### 10.3 Atomic consumption reservation

```text
BEGIN IMMEDIATE
SELECT request_id,state,expires_at FROM authorizations WHERE authorization_id=?
require state='issued'
if now >= expires_at:
  UPDATE state='expired'; project request; COMMIT; reject
UPDATE authorizations
   SET state='executing', consumer=?, updated_at=?
 WHERE authorization_id=? AND state='issued'
require exactly one row changed
project request as consuming in same transaction
COMMIT
```

SQLite's write reservation serializes competing consumers. Only one gets the single durable attempt.

### 10.4 Bulk rollback revocation

Acquire the write reservation before selecting issued rows:

```text
BEGIN IMMEDIATE
SELECT authorization_id,request_id FROM authorizations WHERE state='issued'
for each row:
  UPDATE ... SET state='cancelled' WHERE authorization_id=? AND state='issued'
  if rowcount == 1:
    project cancelled
    increment actual revoked count
COMMIT
```

Never select before `BEGIN IMMEDIATE`; otherwise consumption may win between selection and update while the request is falsely projected cancelled.

Cancellation versus consumption uses the same conditional-state winner rule: both operate under a write transaction and update only `WHERE state='issued'`. Exactly one can change the row. The loser receives a non-cancellable/non-consumable error and MUST NOT project its requested state.

For the hardened profile, compute a default effect key without adding an authorization claim:

```python
effect_key = sha256(engine_canonical({
    "action": claims["action"],
    "parameters": claims["parameters"],
})).hexdigest()
```

Issuer and broker compute it from the already signed action/parameters. Before issuing or beginning consumption, reject an existing `effect_uncertainty` row for that key. Insert it as executing in the same transaction as consumption reservation; retain it when state becomes unknown; delete it in the same commit as simulated, executed, definite pre-dispatch failed, cancelled-before-dispatch (if inserted), or reconciled executed/failed. This blocks an exact duplicate proposal even if it uses a new caller idempotency key. Actions needing a narrower semantic identity require a versioned policy/envelope extension; `0.3.0b1` has no such field and must not claim universal real-world duplicate detection.

### 10.5 Remaining lifecycle transactions

Every state mutation is a conditional compare-and-set under a write transaction:

```text
cancel:
  BEGIN IMMEDIATE
  UPDATE authorizations SET state='cancelled', updated_at=?
   WHERE authorization_id=? AND state='issued'
  require rowcount=1; project request cancelled; COMMIT

deny an authorized request:
  BEGIN IMMEDIATE
  UPDATE authorizations SET state='cancelled', updated_at=?
   WHERE authorization_id=? AND state='issued'
  require rowcount=1
  project request denied with authorization.status='cancelled' and consumption_possible=false
  insert bounded security-state audit; COMMIT

complete:
  BEGIN IMMEDIATE
  UPDATE authorizations SET state=?, receipt_json=?, updated_at=?
   WHERE authorization_id=? AND state='executing'
  require rowcount=1; project matching terminal state
  if state is simulated/executed/failed: DELETE matching effect_uncertainty
  COMMIT

mark unknown after dispatch ambiguity:
  BEGIN IMMEDIATE
  UPDATE authorizations SET state='unknown', receipt_json=?, updated_at=?
   WHERE authorization_id=? AND state='executing'
  require rowcount=1; project outcome_unknown; COMMIT

operator recover interrupted:
  BEGIN IMMEDIATE
  require operator-confirmed abandoned attempt
  UPDATE ... SET state='unknown', receipt_json=<bounded recovery evidence>
   WHERE authorization_id=? AND state='executing'
  require rowcount=1; project outcome_unknown; COMMIT

operator reconcile:
  BEGIN IMMEDIATE
  UPDATE ... SET state=<executed|failed>, receipt_json=<bounded evidence>
   WHERE authorization_id=? AND state='unknown'
  require rowcount=1; project terminal state; clear effect_uncertainty; COMMIT
```

Projection updates the authorization's retained request snapshot and, when sharing a database, the `requests` row plus security-state audit metadata before commit. Optional outbound audit happens afterward. Request admission checks durable pause-all, paused-domain and revoked-principal controls. Broker `revocation_checker` independently checks current authorization/control state both before reservation and immediately before dispatch; unavailable control state denies.

## 11. Authorization state machine

Authorization state machine:

```text
issued
  |-- cancelled
  |-- expired
  `-- executing
        |-- simulated
        |-- executed
        |-- failed    (only definite pre-dispatch rejection)
        `-- unknown
              |-- executed  (explicit reconciliation)
              `-- failed    (explicit reconciliation)
```

Terminal/reconciliation states are durable across restart. Do not automatically change every `executing` row to unknown at startup: another process might still be executing, or the operator may lack evidence. Explicitly recover one ID only after confirming the attempt is abandoned.

## 12. Trusted broker

### 12.1 Fixed action registry

The broker owns a closed map:

```python
fixed_actions = {
    "purchase.place_order": {
        "target": "commerce.place_order",
        "outcome": "reconcilable",  # or idempotent
        "recheck": inventory_recheck,
        "execute": place_order,
    }
}
```

Each entry has exactly target, outcome, recheck and execute. `outcome` is `idempotent` or `reconcilable`. The caller cannot replace these callables.

Construct the broker with both mandatory fail-closed controls:

```python
broker = AuthorizationBroker(
    broker_id="orders-broker",
    authority=public_authorization_verifier,
    store=authorization_store,
    execution_authority=host_owned_execution_authority,
    revocation_checker=current_authorization_is_active,
    expected_policy_hash=engine.policy_hash,
    clock=clock,
    actions=fixed_actions,
)
```

`revocation_checker` must return exactly true only when the authorization remains active. Unavailability or exception denies. It must regard the broker's own `executing` reservation as active during the second check. `expected_policy_hash=engine.policy_hash` rejects authorizations from stale or different policy revisions.

### 12.2 ID-only consumption algorithm

Implement this exact ordering:

```python
import copy

class UnknownOutcome(RuntimeError):
    pass

def require(condition, message):
    if not condition:
        raise PermissionError(message)

def project_receipt(action, checked, result, target_called):
    # Host-owned, action-specific projector: allowlisted scalar IDs/status only.
    receipt = receipt_projectors[action](checked, result, target_called)
    require(isinstance(receipt, dict), "receipt is not an object")
    require(len(signed_canonical(receipt)) <= 8192, "receipt is too large")
    return receipt

def consume_id(authorization_id, consumer):
    record = store.get(authorization_id)             # trusted storage only
    claims = verify_active(record["token"])          # signature/time/audience/policy/revocation
    require(claims["authorization_id"] == authorization_id, "ID mismatch")
    require(consumer == claims["requester"], "requester mismatch")
    spec = fixed_actions[claims["action"]]
    require(spec["target"] == claims["target"], "target mismatch")

    store.begin_consumption(authorization_id, consumer=consumer, now=now())

    try:
        checked = spec["recheck"](copy.deepcopy(claims["parameters"]))
        require(isinstance(checked, dict) and checked.get("eligible") is True, "recheck denied")
        claims = verify_active(record["token"])       # second time/revocation/policy check
    except Exception as error:
        store.complete(
            authorization_id,
            outcome="failed",
            receipt={"error_type": type(error).__name__, "phase": "pre_dispatch"},
            now=now(),
        )
        raise

    if claims["simulation_only"] or not claims["execution_enabled"]:
        return store.complete(
            authorization_id,
            outcome="simulated",
            receipt=project_receipt(claims["action"], checked, None, False),
            now=now(),
        )

    try:
        result = spec["execute"](copy.deepcopy(claims["parameters"]))
        require(isinstance(result, dict), "target result is not an object")
        return store.complete(
            authorization_id,
            outcome="executed",
            receipt=project_receipt(claims["action"], checked, result, True),
            now=now(),
        )
    except Exception as error:
        try:
            store.mark_unknown(
                authorization_id,
                receipt={"error_type": type(error).__name__, "phase": "post_dispatch"},
                now=now(),
            )
        finally:
            raise UnknownOutcome("reconcile before any retry") from error
```

A pre-dispatch rejection may be failed because the target was definitely not called. After dispatch may have started, every exception is indeterminate: target error, timeout, EOF, malformed response, process exit, network loss, or failure persisting the success receipt.

### 12.3 Unknown outcome

Unknown outcome is a safety state, not an error to retry. Rules:

- no automatic retry;
- no new authorization for the same real-world effect until reconciliation or an explicit human decision based on downstream facts;
- use a scoped downstream status query, idempotency key or receipt lookup;
- record actor, final outcome and bounded receipt evidence;
- transition unknown only to executed or failed;
- if evidence remains inconclusive, leave unknown.

If the target may have run but both receipt completion and `mark_unknown` persistence fail (for example disk-full), the durable authorization remains `executing`. Return an unknown/reconciliation-required error anyway. On restart an operator must first confirm the broker attempt is abandoned, use `recover-interrupted` to move that exact ID to unknown, then reconcile. Never reinterpret `executing` as retryable.

For idempotent downstream protocols, the authorized parameters MUST contain the fixed idempotency field and the downstream service MUST enforce it. “Idempotent” is not inferred from HTTP method or hope.

## 13. Declarative MCP adapter

Semantic Gate is not a transparent arbitrary proxy. A Declarative MCP adapter fixes every selectable element:

```json
{
  "version": 1,
  "broker_id": "orders-broker",
  "downstreams": {
    "inventory": {
      "command": ["/absolute/reviewed/inventory-mcp"],
      "pass_environment": ["INVENTORY_TOKEN"],
      "timeout_seconds": 10
    },
    "orders": {
      "command": ["/absolute/reviewed/orders-mcp"],
      "pass_environment": ["ORDERS_TOKEN"],
      "timeout_seconds": 10
    }
  },
  "reads": {
    "inventory.available": {
      "server": "inventory",
      "tool": "inventory.available"
    }
  },
  "actions": {
    "purchase.place_order": {
      "target": "commerce.place_order",
      "server": "orders",
      "tool": "orders.place",
      "recheck_read": "inventory.available",
      "outcome": "reconcilable"
    }
  }
}
```

Validate:

- executable path is absolute;
- command is a bounded list and no shell is used;
- only named environment variables are passed; do not inherit the full environment;
- timeout is bounded, for example 1–300 seconds;
- names match closed patterns;
- server and read mappings exist;
- targets are unique;
- idempotent actions declare an `idempotency_field` present in authorized parameters and required by the corresponding policy parameter schema; validate this cross-reference at host startup, not only at execution;
- reconcilable actions do not claim an idempotency field;
- target transport exceptions are translated to Unknown outcome.

The host may register declarative reads into the engine read registry. It exposes action callables only to the trusted broker.

The downstream stdio MCP client must perform initialize/initialized before calls, bind every response ID, cap requests and responses at 1 MiB, reject malformed UTF-8/JSON, enforce the configured timeout, and terminate its direct child on close or failure. The `0.3.0b1` client does not create or kill a descendant process group and sends stderr to the null device; therefore configured executables must not daemonize or spawn persistent descendants. Hardened hosts should use an OS sandbox/container/process group that owns and terminates every descendant before passing credentials.

Messages are one compact UTF-8 JSON-RPC object per newline. `tools/call` uses `{ "name": fixed_tool, "arguments": authorized_parameters }`; the reference recheck forwards the complete authorized parameter object unchanged to the configured read. If a read needs another shape, add a fixed host-owned projector to a versioned adapter schema—never accept a caller transformation. Require matching response ID, `jsonrpc="2.0"`, no error, object result, `isError != true`, and object `structuredContent`; all post-dispatch transport/decoding failures map to Unknown.

The beta also contains legacy distributed node leases and fixed recipe plugins. They are not equivalent to the version-2 authorization broker: legacy leases have a separate replay table and do not provide the durable executing/unknown/reconciliation model described here. Do not use them as proof of version-2 enforcement. If implemented, a recipe plugin still must use a fixed absolute executable, fixed argv template, exact parameter placeholders, no shell, minimal fixed environment, timeout no greater than 300 seconds, and bounded output. A distributed production design needs a version-2-equivalent linearizable store and unknown-outcome protocol.

## 14. API boundaries

### 14.1 SDK boundary

The reference SDK/controller exposes:

```text
list_actions(principal)
explain_action(action, principal)
request_action(principal, payload, host_context)
get_request(request_id, principal)
list_requests(principal)
cancel(request_id, principal)
```

Agent-controlled consumption uses a separate, narrowly scoped broker capability. A reproducible HTTP form is:

```text
POST /v1/authorizations/{authorization_id}/consume
Authorization: Bearer <consume-scoped capability>
Content-Type: application/json

{}
```

The broker derives `consumer` from the authenticated capability; no consumer/requester appears in the body. It loads the host-stored token by ID, then applies section 12.2. Return 200 for simulated/executed, 403 for ownership/audience/policy/revocation denial, 409 for cancelled/expired/already-reserved state, and 502 with `{ "state": "outcome_unknown", "retry_allowed": false }` for post-dispatch ambiguity. Never return the bearer token. The reference coordinator/MCP does not expose this route; deployments must provide this broker API or an equivalent host SDK call if agents are to control consumption remotely.

Host-only SDK methods may include verified approval ingestion, authorization signing, target registration, control mutation, recovery and reconciliation. Keep them in a different object/process/capability from agent methods.

### 14.2 HTTP boundary

HTTP requirements:

- authenticate principals with scoped capabilities;
- derive identity from authentication, not JSON;
- enforce method/path allowlists and exact schemas;
- cap request bodies (for example 1 MiB);
- require strict JSON content type for mutations;
- enforce configured origins for browser/admin surfaces;
- forbid wildcard service binds in the supplied server (`0.0.0.0` and `::`); bind to a private interface or place behind an authenticated proxy;
- add no-sniff, no-referrer, restrictive CSP and frame denial;
- do not log request bodies or bearer authorizations.

Require `Content-Type: application/json` for JSON mutation routes before decoding. The `0.3.0b1` `SemanticGateApplication` does not currently enforce this header, so place it behind a validating proxy or patch the application before public-network deployment; this is a documented beta boundary gap.

The reference capability authority uses at least 32 random master-key bytes and enabled principal roles `agent`, `admin`, `service`, `observer`. For principal ID `p`, its deterministic bearer is `sg1_` plus unpadded URL-safe base64 of `HMAC-SHA256(master_key, b"capability\0" + p.encode())`. Authentication compares against configured principals in constant-time and then rechecks enabled/role state. Equivalent external authentication is acceptable if it provides the same host-derived, revocable scoped identity and keeps admin sessions separate.

Agent routes and methods are exactly:

```text
GET  /api/v1/actions
POST /api/v1/requests
GET  /api/v1/requests/{request_id}
GET  /api/v1/requests
POST /api/v1/requests/{request_id}/cancel
```

All agent routes require an enabled agent/service/admin bearer and derive ownership from it. `POST /api/v1/requests` accepts exactly the proposal object from section 5.1 and returns HTTP 201 with the public request snapshot from section 5.3. `GET /api/v1/requests` returns HTTP 200 with a JSON array of only the caller's snapshots, newest first, server-capped at 500. `GET /api/v1/requests/{id}` and successful cancel return one owned snapshot with HTTP 200. Unknown/malformed/conflicting input returns `400 {"error":"bounded message"}`; absent/invalid auth returns 401; authenticated ownership/role denial returns 403; unknown route returns 404. Responses use `application/json`, `Cache-Control: no-store`, and never contain `authorization_token` or credentials.

The complete reference HTTP surface also includes `GET /health`, `GET|POST /login`, `GET /` for the admin panel, `POST /mcp`, `POST /api/v1/audit-observations`, `POST /admin/requests/{id}/approve`, `POST /admin/requests/{id}/deny`, and `POST /admin/controls`. Agent capability tokens MUST NOT authorize the admin routes. Browser mutations require an exact Origin allowlist, an expiring signed admin session, `HttpOnly` and `SameSite=Strict` cookies, and a session-derived CSRF token. Secure cookies are the default outside explicit local testing.

Approval, policy mutation, signer roster, controls, broker registration, token retrieval, recovery and reconciliation are absent from agent capabilities.

### 14.3 MCP boundary

An agent-facing MCP server exposes only proposal/read/cancel tools. Example tool arguments:

```json
{
  "action": "purchase.place_order",
  "parameters": {},
  "context": {},
  "idempotency_key": "stable-key",
  "minimum_control": "policy"
}
```

The MCP host injects principal and trusted context. It does not accept them as tool arguments. It never exposes approval, minting, target registration, credential access, bearer retrieval, control mutation or direct execution.

After MCP initialization, expose exactly these tools:

```json
{
  "list_actions": {"type":"object","properties":{},"additionalProperties":false},
  "explain_action": {"type":"object","properties":{"action":{"type":"string"}},"required":["action"],"additionalProperties":false},
  "request_action": {"type":"object","properties":{"action":{"type":"string"},"parameters":{"type":"object"},"context":{"type":"object"},"idempotency_key":{"type":"string"},"minimum_control":{"type":"string","enum":["policy","ask","step_up"]}},"required":["action","parameters","context","idempotency_key"],"additionalProperties":false},
  "get_request": {"type":"object","properties":{"request_id":{"type":"string"}},"required":["request_id"],"additionalProperties":false},
  "cancel_request": {"type":"object","properties":{"request_id":{"type":"string"}},"required":["request_id"],"additionalProperties":false}
}
```

`tools/list` returns these schemas. A successful `tools/call` result is `{ "content":[{"type":"text","text":"<canonical JSON value>"}], "structuredContent":<same JSON value>, "isError":false }`. Invalid tool input/ownership returns a JSON-RPC error with the original ID; never serialize a Python traceback, secret or bearer. The stdio server uses standard codes -32700 parse error, -32600 invalid request, -32601 method not found, -32602 invalid params, and -32603 internal error. Consumption is intentionally not one of these coordinator tools; use the separate scoped broker contract in section 14.1.

For stdio MCP, implement `new -> initialize_responded -> ready`: accept a supported `initialize`, return server/tool capabilities, require the `notifications/initialized` notification, then permit `tools/list` and `tools/call`. Validate JSON-RPC IDs (string up to 256 characters, signed-64 integer, or finite float bounded to 2^53), exact parameter objects, UTF-8 and the 1 MiB frame cap. Return standard JSON-RPC errors without process crashes. The simpler HTTP `/mcp` compatibility surface may omit this lifecycle, so document and test the two transports separately rather than assuming identical protocol strictness.

The content-free observation payload is closed: `event_id`, `phase`, `operation`, `semantic_class`, `outcome`, `occurred_at`, and `metadata`. Phase is attempted/completed; outcome is started/succeeded/failed/cancelled/unknown. Metadata has at most 16 flat scalar labels from a host allowlist (for example surface, node, harness, duration_ms, status, error_type, dropped_events, toolset, version); strings are bounded labels, not arbitrary text.

### 14.4 Audit boundary

Audit metadata should be closed and content-free:

```json
{
  "request_id": "req_random",
  "event": "authorization_executing",
  "actor": "authorization-store",
  "at": 1700000020,
  "metadata": {"authorization_id": "auth_random"}
}
```

Never include parameters, output, prompt, command, message, body, query text, file contents, credentials or arbitrary summaries. Security-state audit rows inserted in the same SQLite transaction may deliberately fail closed with that transaction. Optional outbound audit/observability delivery happens after commit and must be fail-open and outcome-neutral: its failure must not rewrite the already-determined protected result.

## 15. Administrative recovery and rollback

Administrative tools MUST reject a missing/mistyped database path and verify the expected schema read-only before opening it mutably. Otherwise a new empty SQLite file can create false rollback assurance.

Required metadata-only operations:

```sh
semantic-gate-authorizations list \
  --database /absolute/path/gate.sqlite3 \
  --state issued

semantic-gate-authorizations revoke-issued \
  --database /absolute/path/gate.sqlite3 \
  --actor human:operator

semantic-gate-authorizations recover-interrupted \
  --database /absolute/path/gate.sqlite3 \
  --authorization-id auth_example \
  --actor human:operator

semantic-gate-authorizations reconcile \
  --database /absolute/path/gate.sqlite3 \
  --authorization-id auth_example \
  --actor human:operator \
  --outcome executed \
  --receipt-file /absolute/path/bounded-receipt.json
```

Listing excludes `token_json`. Receipt files must be JSON objects. Recovery changes only one operator-confirmed abandoned `executing` record to unknown. Reconciliation changes only unknown to executed/failed.

Before recovery/reconciliation persistence, pass operator evidence through the same action-specific closed receipt projector used by normal completion. Allow only configured scalar identifiers/status fields, reject nested arbitrary bodies and credentials, and enforce an 8 KiB canonical encoded limit. The `0.3.0b1` CLI currently accepts any JSON object, so sensitive deployments must wrap or patch it before use; this is a beta administration gap.

For a crashed request-idempotency reservation, do not delete or reuse the row. A hardened admin operation obtains `BEGIN IMMEDIATE`, requires status `reserved`, records operator/evidence, and changes it to terminal `abandoned`; the old principal/key remains permanently non-reusable. Only after confirming no downstream effect or authorization exists may the caller submit a new proposal with a new idempotency key. `0.3.0b1` does not ship this command, so deployments either implement it or retain the fail-closed reserved row.

Rollback procedure:

1. Stop accepting new proposals.
2. Pause affected actions/domains.
3. Bulk revoke all still-issued authorizations transactionally.
4. List executing records; confirm whether each broker attempt remains active.
5. For a confirmed abandoned attempt, recover that exact ID to unknown.
6. Reconcile unknown records from downstream status/receipt evidence.
7. Back up the database and configuration.
8. Disable execution and restore `simulation_only` before rolling software back.
9. Restore previous package/policy only after no uncertain execution remains.
10. Verify agents cannot reach old credentials/raw tools introduced by rollback.

## 16. Deployment sequence

### 16.0 Package and coordinator startup

For the Python reference package:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install "semantic-gate[approvals]==0.3.0b1"
semantic-gate-server --help
semantic-gate-mcp --help
semantic-gate-sign-approval --help
semantic-gate-adapter-check --help
semantic-gate-authorizations --help
```

The coordinator requires four independent secrets: `SEMANTIC_GATE_MASTER_KEY`, `SEMANTIC_GATE_APPROVAL_KEY`, `SEMANTIC_GATE_AUTHORIZATION_KEY`, and `SEMANTIC_GATE_ADMIN_PASSWORD`. The first three are independent high-entropy values; never reuse one purpose for another. Supply explicit bind, port, origin, catalog, principals, credentials registry and database paths. Never bind the reference coordinator to `0.0.0.0` or `::`; use a private interface or authenticated reverse proxy. The credentials registry and secret environment files are host-only and excluded from source control.

Minimal catalog file:

```json
{
  "version": 1,
  "actions": {
    "purchase.place_order": {
      "domain": "purchase",
      "risk": "R3",
      "effect": "external_write",
      "summary": "Place one reviewed order",
      "approval": "step_up",
      "privacy_classes": [],
      "constraints": []
    }
  }
}
```

`build_policy` skips actions whose effect is `read`/`prohibited` or approval is `none`/`prohibited`; R3 or approval `step_up` creates `human_step_up`, otherwise `human_approve_once`. Hardened deployments should validate the catalog as a closed schema before calling the beta builder, because the reference builder reads known fields but does not reject extras.

Principals file:

```json
{
  "principals": {
    "example-agent": {"role": "agent", "enabled": true},
    "control-panel": {"role": "admin", "enabled": true},
    "audit-observer": {"role": "observer", "enabled": true}
  }
}
```

Roles are exactly agent/admin/service/observer. Only enabled agent/service/admin principals become workflow proposers; observer is audit-only.

Host-only credentials registry (never commit a populated file):

```json
{
  "credentials": {
    "orders-api": {
      "adapter": "orders-mcp",
      "kind": "api-token",
      "value": "replace-from-secret-store",
      "disabled": false
    }
  }
}
```

Public inventory exposes only credential ID, adapter, kind and available/missing/disabled status. The `value` is returned only to trusted host code.

### 16.1 Phase A: catalogue and simulation

1. Inventory every effect path, credential owner and raw agent tool.
2. Define one exact semantic action per reviewed effect.
3. Create closed parameter schemas and fixed targets.
4. Start with `simulation_only` and `execution_enabled=false`.
5. Implement agent proposal/status/cancel APIs.
6. Persist request snapshots, audit metadata and idempotency reservations.
7. Add real notification and human Ed25519 approval transport, but do not dispatch.
8. Verify approved requests end at authorized and the agent can stop indefinitely.

### 16.2 Phase B: broker shadowing

1. Put target credentials in a dedicated broker/adapter host.
2. Configure fixed commands, tools, environment allowlists and target mappings.
3. Add durable signed authorizations and ID-only broker consumption.
4. Exercise simulation consumption (`target_called=false`).
5. Test expiry, revocation, cancellation, concurrency, crash and unknown reconciliation.
6. Record the path as shadowed, not enforced, while raw bypasses remain.

### 16.3 Phase C: enforcement promotion

For one action at a time:

1. Review policy and adapter config.
2. Ensure post-approval and consumption-time rechecks exist.
3. Ensure downstream has idempotency or reconciliation.
4. Remove the raw effectful MCP/tool from the agent configuration.
5. Remove downstream credentials from the agent process and filesystem access.
6. Restrict network/OS access so only the broker can reach the effect target.
7. Prove an approved brokered attempt succeeds.
8. Prove the same direct unapproved attempt is technically denied.
9. Enable execution for only that action and retain an emergency pause.
10. Mark that action enforced; do not generalize to unrelated actions.

### 16.4 Bypass removal

Bypass removal is deployment-specific and mandatory. Check:

```text
[ ] agent has no raw target credential
[ ] agent has no direct effectful MCP registration
[ ] agent cannot choose broker command/tool/target
[ ] agent cannot reach target network endpoint directly
[ ] filesystem/secret manager denies target secret to agent
[ ] alternate shell/browser/GUI route is removed or separately gated
[ ] admin approval and key enrollment are inaccessible to agent
[ ] authorization signer inaccessible to broker verifier process
[ ] old version-1 inline effect path disabled
[ ] emergency operator path is audited and not agent-callable
```

Do not remove a shared workaround until every semantic action depending on it has an enforced replacement.

## 17. Migration

### 17.1 Version 1 to version 2

Version 1 may approve and execute inline. Version 2 separates approval and consumption.

Migration:

1. Back up policy and SQLite database.
2. Add version-2 authorization config (`audience`, `ttl_seconds`).
3. Install a host-only signer and durable authorization store.
4. Change execute behavior to issue authorization and return `authorized`.
5. Remove target credentials from the engine.
6. Build a trusted broker with public verifier, current policy hash, revocation checker and fixed action map.
7. Add explicit agent/operator consumption by authorization ID.
8. Add unknown recovery/reconciliation tooling.
9. Keep execution disabled through all tests.
10. Migrate one action, remove its bypass, then promote it.

Apply database changes as monotonic migrations under an exclusive maintenance window. Version 1 consists of `requests`, `audit`, `observations`, `controls`, and `request_idempotency`; older v1 databases may lack `request_idempotency.status` and have no `authorizations`, evidence, effect or migration tables. Version 2 migration is:

```sql
BEGIN EXCLUSIVE;
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS request_idempotency (
  principal TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  request_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(principal,idempotency_key)
);
ALTER TABLE request_idempotency ADD COLUMN status TEXT NOT NULL DEFAULT 'complete';
-- If the column already exists, skip only this ALTER after PRAGMA table_info validation.
-- Execute the exact CREATE TABLE IF NOT EXISTS statements from section 10 for:
-- authorizations, approval_evidence, notification_evidence, effect_uncertainty.
INSERT INTO schema_migrations(version,applied_at) VALUES(2,CAST(strftime('%s','now') AS INTEGER));
COMMIT;
```

Before the transaction, back up the database and stop all coordinators/brokers. Inside it, inspect `PRAGMA table_info` and conditionally apply only missing columns/tables; do not ignore other SQL errors. Validate every existing idempotency row: non-empty principal/key/fingerprint, status becomes `complete`, and its request ID resolves or is quarantined for operator review. Backfill no authorization or evidence row from a version-1 request. Existing request rows remain historical; new version-2 proposals receive fresh hashes, evidence and authorizations. During a rolling upgrade, keep all brokers stopped until every coordinator uses schema version 2. Downgrade is restore-from-backup, not reverse DDL: version-1 code must not open a database after version-2 execution has begun.

Existing version-1 requests should not be silently converted into executable version-2 authorizations. Reproposal under the new policy creates new hashes and fresh approval.

### 17.2 Key rotation

For approval keys, enroll a new public key, accept both during a bounded overlap, then remove the old key after outstanding approvals expire. For authorization keys, version issuer/key IDs or run overlapping verifiers; never reuse approval keys as authorization keys. Revoke outstanding issued authorizations before removing the only verifier able to reconcile them.

## 18. Acceptance tests

A conforming implementation needs deterministic tests for at least the following.

### 18.1 Policy and proposal

```text
[ ] unknown policy fields rejected
[ ] non-finite JSON rejected
[ ] invalid DAG/cycle/unknown dependency rejected
[ ] execute without notify+approval rejected
[ ] enforcing approval without post-approval recheck rejected
[ ] simulation_only + execution_enabled true rejected
[ ] parameter additional properties rejected
[ ] unauthorized principal rejected
[ ] caller floor can strengthen but never weaken policy
[ ] caller-supplied trusted context/identity rejected
[ ] same idempotency key + same fingerprint returns same request
[ ] same key + different fingerprint conflicts
[ ] crash after reservation does not repeat backend callbacks
```

### 18.2 Approval

```text
[ ] unknown key rejected
[ ] service/agent actor rejected
[ ] actor/key mismatch rejected
[ ] stale, expired and future signatures rejected
[ ] request ID/hash mismatch rejected
[ ] insufficient assurance rejected
[ ] duplicate evidence ID rejected
[ ] malformed signature rejected
[ ] valid Ed25519 approval reaches authorized, not executed
[ ] multiple approvals preserve deterministic evidence-keyed provenance
```

### 18.3 Authorization and broker

```text
[ ] public snapshot contains ID metadata but no bearer token
[ ] broker cannot accept/import caller token
[ ] wrong issuer/audience/requester/action/target/parameters rejected
[ ] stale policy hash rejected
[ ] unavailable revocation checker rejects
[ ] expiry before reservation rejects
[ ] expiry/revocation during slow recheck rejects before dispatch
[ ] two consumers across two SQLite connections produce one attempt
[ ] cancellation versus consumption has one consistent winner
[ ] bulk revocation begins write transaction before selection
[ ] replayed record_issued preserves executing/terminal state and timestamp
[ ] successful effect + receipt persistence failure becomes unknown
[ ] timeout/EOF/malformed response after dispatch becomes unknown
[ ] unknown cannot be consumed/retried
[ ] only explicit reconciliation resolves unknown
```

### 18.4 Projection and restart

```text
[ ] token and full authorized snapshot commit atomically
[ ] shared request row updates in same transaction
[ ] separate-store orphan is repaired from retained snapshot
[ ] compare-and-swap repair cannot overwrite a newer state
[ ] authorized, consuming and unknown survive restart
[ ] startup performs no global executing-to-unknown or pending-expiry sweep
[ ] pending lost workflow can be explicitly cancelled and reproposed
[ ] admin CLI rejects missing/unrelated database without creating tables
```

### 18.5 MCP and deployment

```text
[ ] executable must be absolute
[ ] shell invocation impossible
[ ] caller cannot select server/tool/target
[ ] only allowlisted environment reaches downstream
[ ] raw effectful MCP absent from agent after promotion
[ ] direct credential access denied
[ ] local simulation calls no effect target
[ ] local enforcing test calls exactly one fixed target
[ ] post-dispatch transport ambiguity becomes unknown
```

Run tests with warnings/resource leaks treated as failures. Build a clean wheel/package, install into a new environment, run examples from the installed package, compile all source/examples, scan tracked history and current files for secrets/private deployment identifiers, and independently review the immutable tree before publication.

## 19. Minimal end-to-end package assembly

This uses the exact `0.3.0b1` class and method names. `policy_document` is the complete JSON object from section 4.3; `approval_key` and `authorization_key` are persistent independent host-loaded 32-byte-or-longer secrets; `roster`, `signed_decision`, `fixed_actions`, `bound_notifier`, and `authenticated_principal` are host-owned objects defined by the preceding sections.

```python
import time
from semantic_gate import (
    AuthorizationBroker, ExecutionAuthority, SignedApprovalBridge,
    SQLiteAuthorizationStore, load_policy,
)
from semantic_gate.controller import GateControl
from semantic_gate.coordinator import CoreBackend
from semantic_gate.storage import Ledger

clock = lambda: int(time.time())
policy = load_policy(policy_document)
auth_store = SQLiteAuthorizationStore("gate.sqlite3")
ledger = Ledger("gate.sqlite3")
backend = CoreBackend(
    policy,
    approval_key=approval_key,
    authorization_key=authorization_key,
    authorization_store=auth_store,
    notifier=bound_notifier,
    clock=clock,
)
controller = GateControl(backend, ledger, clock=clock, authorization_store=auth_store)

# Agent proposal; identity and trusted context come from the host transport.
request = controller.request_action(
    principal=authenticated_principal,
    payload=agent_payload,
    host_context=trusted_context,
)
# It stops at waiting_for_approval; no target invocation occurs.

# Separate host-only signed-human transport.
bridge = SignedApprovalBridge(roster, backend)
authorized = bridge.approve(signed_decision)
# It stops at authorized; signed expires_at is preserved; no target invocation occurs.

# Separate trusted broker. In a split process use an Ed25519 public verifier.
broker = AuthorizationBroker(
    broker_id=policy["authorization"]["audience"],
    authority=backend.engine.authorization_authority,
    store=auth_store,
    execution_authority=ExecutionAuthority("reviewed-target-host"),
    revocation_checker=current_authorization_is_active,
    expected_policy_hash=backend.engine.policy_hash,
    clock=clock,
    actions=fixed_actions,
)

# Later, the agent independently chooses whether to request ID-only consumption.
if agent_still_wants_effect:
    result = broker.consume_id(
        authorized["authorization"]["authorization_id"],
        consumer=authenticated_principal,
    )
```

The final call is not performed automatically by approval. The agent can omit it forever.

## 20. Operational security checklist

```text
[ ] separate secrets for capability auth, approval transport and authorization signing
[ ] private keys and credentials excluded from source control
[ ] broker receives verifier, not signer, where possible
[ ] services bind only to intended private/authenticated interfaces
[ ] request body and concurrency limits configured
[ ] SQLite backups include WAL-consistent state
[ ] clocks synchronized and time anomalies fail closed
[ ] emergency pause tested
[ ] revocation checker tested unavailable/revoked/active
[ ] content-free audit retention bounded
[ ] database file permissions restrict bearer-token table
[ ] core dumps/debug logs cannot expose token_json
[ ] approval roster changes require separate human administration
[ ] policy changes produce a new policy hash
[ ] old-policy tokens rejected immediately by current broker
[ ] downstream reconciliation procedure documented and tested per action
```

## 21. Beta limitations

This design is public beta 0.3.0b1 and is not production-ready by default.

Known limitations and required judgment:

- SQLite supports a strong single-host reference path but distributed deployments need an equivalent linearizable reservation/projection design.
- The reference parameter schema intentionally treats nested object/array values opaquely; domain adapters must validate them.
- Notification truth depends on the host adapter.
- Human key custody, revocation and recovery are deployment responsibilities.
- There is no universal reconciliation API; each effect target needs a bounded status/receipt strategy.
- Exactly-once effects are not claimed. The design provides one durable attempt and an explicit unknown state.
- Content-free auditing trades forensic detail for privacy; protected downstream systems may need their own secure audit.
- Existing systems remain shadowed until credentials, raw tools and alternate effect paths are removed.
- Version-1 compatibility must not be mistaken for version-2 security.
- A passing test suite cannot prove deployment-specific bypass removal.
- The reference JSON loaders do not reject duplicate object names at every entry point; hardened front doors must use the duplicate-rejecting parser in section 3. This is a beta parser-hardening gap.
- Process-local approval/notification consumed-ID sets are not durable multi-process replay tables; use section 10's evidence tables for hardened deployments.
- Complete read/recheck/effect results may appear in reference gate evidence and receipts; use an action-specific bounded receipt projector before sensitive enforcing deployment.
- Authorization and approval canonicalizers enforce exact fields and strict serializability but do not independently apply every engine size/depth/node limit; front-door adapters must impose equivalent bounds. This is a beta hardening gap.
- A crash after durable idempotency reservation has no generic automated repair command in `0.3.0b1`; it deliberately remains blocked pending operator investigation.
- Legacy distributed node leases do not implement the version-2 durable unknown/reconciliation protocol and must not be presented as equivalent enforcement.

The correct public claim is: Semantic Gate can determine and enforce permission requirements for exact actions when deployed behind a trusted broker and after all direct effect paths are removed. It is not correct to claim that “everything is gated” merely because policy decisions or approval screens exist.

## 22. Definition of done

An implementation is complete for one action only when all of these are true:

```text
1. The exact semantic action and closed parameters are catalogued.
2. Policy computes the minimum control; caller cannot reduce it.
3. Request identity, trusted context, workflow and parameters are canonically bound.
4. Idempotency is durably reserved before callbacks.
5. Notification and enrolled-human approval evidence are exact and current.
6. Approval ends at a host-stored, signed, expiring authorization.
7. The agent receives only metadata and chooses whether/when to consume.
8. The broker accepts ID only, validates current policy/revocation twice, and owns a fixed target.
9. One attempt is durably reserved before dispatch.
10. Post-dispatch ambiguity becomes unknown and cannot auto-retry.
11. Recovery/reconciliation and rollback are tested.
12. The raw credential/tool/network/alternate bypass is technically denied.
13. An approved brokered attempt succeeds and an unapproved direct attempt fails.
14. The action—not the entire environment—is marked enforced.
```

That is Semantic Gate: permission is bounded and durable; workflow remains agent-owned; execution authority remains broker-owned; uncertainty fails closed.