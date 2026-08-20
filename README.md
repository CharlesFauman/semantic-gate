# Semantic Gate

Deterministic, semantic permission gates for agent tools.

Semantic Gate sits between an agent and effectful tools. Agents propose actions
such as `calendar.create_event` or `purchase.place_order`; a checked-in workflow
then requires deterministic preconditions, notifications, approval evidence and
last-moment rechecks before the target tool can run.

It is agent-framework and tool-provider agnostic. A target adapter can wrap an
API, local function, command broker, another MCP server, or any other host-owned
capability. The optional coordinator service, direct HTTP client, mobile control
panel and distributed node-broker/plugin SDK use the same semantic action model.

Start extending with [`docs/INTEGRATION_GUIDE.md`](docs/INTEGRATION_GUIDE.md),
which compares SDK, HTTP, MCP, observer, fixed-recipe and node-broker options and
links runnable examples under `examples/integrations/`.

> **Status:** alpha. All bundled examples are simulation-only. The default MCP
> server installs a deny-all approval verifier and no execution authority.
> The coordinator added in v0.2 also generates simulation-only policy and expires
> unresolved requests on restart; it does not claim crash-safe live execution.

## Why

Prompt instructions such as “ask before buying” are useful guidance, but not a
security boundary. Semantic Gate turns that intent into a deterministic state
machine:

```text
normalize request
  → validate semantic schema
  → call read-only precondition tools
  → notify the human
  → wait for exact request-bound approval evidence
  → re-check time-sensitive conditions
  → require host-owned execution authority
  → call the registered target at most once in the locked in-memory process
```

The model cannot skip a node, invent approval evidence, or call the target
through the gateway directly.

## Core properties

- **Semantic actions:** policy names intent, not raw APIs or shell commands.
- **Principal allowlists:** each action declares which host-authenticated agent identities may propose it.
- **Trusted context:** security-relevant facts are injected by the host and cannot be supplied through MCP.
- **Closed schemas:** unknown parameters and unknown actions fail closed.
- **Policy-owned control:** policy decides the required approval level. A caller
  may supply only `minimum_control=policy|ask|step_up`; this is a floor and can
  never reduce the policy-selected requirement.
- **v0.1 schema scope:** scalar fields support bounds/enums; object and array
  fields are opaque JSON values rather than recursively validated.
- **Bounded JSON domain:** inputs reject non-string object keys, non-JSON
  Python values, excessive nesting/collections/strings, and integers outside
  the signed 64-bit range; stdio messages are capped at 1 MiB.
- **Gate DAGs:** dependencies are validated, cycle-free and deterministic.
- **Mandatory paths:** every execute node must depend on both notification and approval.
- **Out-of-band approval:** approval ingestion is a host API, never an agent-callable MCP tool.
- **Exact binding:** approval evidence is bound to request ID, request hash,
  approval-gate ID, unique evidence ID and expiry.
- **Exact human decisions:** the authenticated panel posts the immutable request
  ID/hash, approval-gate ID and fixed deadline. Missing, stale, mismatched,
  expired, terminal and replayed decisions fail with HTTP 409; terminal history
  is never rewritten. The password panel cannot claim step-up assurance.
- **No-JavaScript decision transport:** login and approve-once/deny are ordinary
  server-rendered POST forms. Decision forms carry the exact immutable challenge
  plus a session-bound CSRF token; the server still requires an exact allowed
  Origin. JSON clients remain a separate transport.
- **Delivery-anchored review window:** an approval challenge is unavailable until
  trusted notification delivery is confirmed. Its deadline is the earlier of
  the policy TTL after delivery and six hours after request creation, enforced
  by the backend for panel and host transports alike.
- **TOCTOU protection:** enforcing workflows require a post-approval recheck
  after every approval before execution.
- **Idempotency:** keys are bound to exact canonical requests.
- **In-process serialization:** concurrent approval callbacks cannot execute one request twice.
- **Notification binding:** delivery evidence is bound to request ID/hash, gate,
  recipient, template hash, delivery time and a unique notification ID.
- **Durable notification outbox foundation:** SQLite schema v1 stores stable,
  deduplicated notification identities bound to that same exact tuple, with
  pending/delivered/unknown states, attempt/backoff data and token-safe
  claim/complete/release operations that survive restart. A host notifier must
  still perform delivery and provide truthful delivery evidence.
- **Provider health projection:** deployments may supply bounded outbox/relay
  status for `/health` and the authenticated panel. Delivery ambiguity remains
  explicit rather than being retried as though a send definitely failed.
- **Policy-owned auto-approval:** an optional checked-in document may auto-approve
  the approval gate. The bundled standing rule is simulation-only and **automatic
  except communications and spending**: every catalogued non-prohibited action is
  auto-approved unless its required `gate_class` catalogue metadata is
  `human_communication` (communication/sending/disclosure to a person or external
  recipient) or `human_spending` (spending/transferring/purchasing/committing
  money), which always keep the human gate; `prohibited` entries are not
  requestable at all. Classification is metadata-only: action names and caller
  parameters never reclassify an action, so an internal deploy or a read-only
  balance query classified `automatic` is not overexcluded. Scoped rules bind one
  canonical repository, exact refs, declared deploy target/environment,
  host-authenticated requester/node, closed parameter constraints and a commit
  identity. Rules are host-owned; agents cannot create, edit, enable, disable or
  pause them.
- **Auto-approval is not execution:** matched requests still pass schema
  validation, prechecks, the approval gate, the post-approval recheck and
  single-request evidence/audit. `execution_enabled=false` remains a separate
  hard stop, and the standing rule refuses to apply at all while execution is
  enabled.
- **Bounded decision cards:** out-of-band notices project only closed,
  schema-owned presentation fields, deterministically sanitized, length-bounded
  and escaped. Parameters, prompts, commands, paths, message bodies and
  credentials are never projected.
- **Separated failure feeds:** gate decisions, policy denials, gate errors,
  withdrawals and ordinary tool telemetry are distinct. A nonzero exit, timeout,
  interrupt or cancellation is never presented as a Semantic Gate decision.
- **Separated tool roles:** read gates and effectful targets live in different registries.
- **Dual execution control:** live execution needs policy enablement **and** a host-owned `ExecutionAuthority` object.
- **Safe MCP defaults:** the CLI MCP server has no trusted approval verifier or execution authority.

## Quick start

```sh
python -m pip install -e .
python -m unittest discover -s tests -v

semantic-gate-mcp \
  --policy examples/calendar-booking/workflow.json \
  --principal example-agent \
  --trusted-context-json '{"direct_user_request":true}'
```

Configure any MCP client to launch that stdio command. The server exposes only:

- `list_actions`
- `explain_action`
- `request_action`
- `get_request`
- `cancel_request`

There is deliberately no MCP tool for approval ingestion or execution.

## Example workflow

```json
{
  "version": 1,
  "mode": "simulation_only",
  "execution_enabled": false,
  "workflows": {
    "device.power_off": {
      "description": "Power off an allowlisted device after safety checks and approval.",
      "principals": ["example-agent"],
      "target_tool": "device.power_off",
      "parameter_schema": {
        "type": "object",
        "additionalProperties": false,
        "required": ["device_id"],
        "properties": {
          "device_id": {"type": "string", "enum": ["example-display"]}
        }
      },
      "gates": [
        {"id":"schema","kind":"schema","requires":[]},
        {"id":"safe","kind":"tool","requires":["schema"],"tool":"device.safe_to_power_off","input":{"device_id":"$parameters.device_id"},"expect":{"path":"safe","op":"eq","value":true},"recheck":false},
        {"id":"notify","kind":"notify","requires":["safe"],"recipient":"human_owner","template":"Review device request"},
        {"id":"approval","kind":"approval","requires":["notify"],"level":"human_approve_once","ttl_seconds":300},
        {"id":"recheck","kind":"tool","requires":["approval"],"tool":"device.safe_to_power_off","input":{"device_id":"$parameters.device_id"},"expect":{"path":"safe","op":"eq","value":true},"recheck":true},
        {"id":"execute","kind":"execute","requires":["recheck"],"tool":"device.power_off","simulation_only":true}
      ]
    }
  }
}
```

See [`examples/`](examples/) for calendar, purchase and device-control flows.

## Coordinator, SDK and distributed brokers

`semantic-gate-server` runs a dependency-free HTTP coordinator with:

- proposal/status/cancellation REST endpoints;
- authenticated, idempotent audit-only permission observations;
- proposal-only MCP over HTTP;
- a keyboard-accessible, JavaScript-free control panel that leads with pending
  decisions and separates decision, denial and telemetry feeds;
- SQLite request snapshots, audit events, emergency controls and a durable
  notification-outbox foundation;
- host-derived principal capabilities;
- redacted credential-binding inventory;
- an optional declarative `--auto-approval` policy path that wires the checked-in
  auto-approval document, the authoritative catalogue and the live execution flag
  into the effective backend the panel reports on.

`SemanticGateClient` provides the same proposal contract without MCP. Local and
remote execution plugins implement `ActionPlugin` and run behind `NodeBroker`.
The broker accepts only signed, expiring, single-use leases addressed to an exact
node, plugin, semantic action and canonical parameter hash.

`POST /api/v1/audit-observations` is an outcome-neutral observation lane for
host hooks. The bearer capability supplies the principal; callers may submit
only bounded operation/class/outcome labels and flat scalar metadata. Raw
prompts, arguments, results, commands, file contents and credentials do not
belong in this endpoint. The default ledger retains at most 100,000 observations
and 200,000 audit rows; hosts may choose lower bounds. Observation ingestion is
not approval or evidence that an old direct-capability bypass has been removed.
For least privilege, hosts can issue a dedicated `observer` principal. Observer
capabilities can submit observations but receive HTTP 403 from action, request
and MCP surfaces, and observer principals are excluded from generated action
policies.

The bundled `RecipePlugin` demonstrates safe local control: fixed executable,
fixed argument vector and allowlisted parameter values, with no shell. It is
appropriate for reviewed native helpers or checked-in automation recipes, not
arbitrary script text or GUI coordinates. Recipe subprocesses receive a minimal
fixed environment rather than inheriting coordinator or broker credentials.

See [`docs/PLUGINS.md`](docs/PLUGINS.md) and
[`docs/DESIGN_RESEARCH.md`](docs/DESIGN_RESEARCH.md).

## Embedding with arbitrary tools

```python
from semantic_gate import (
    ExecutionAuthority,
    GatewayEngine,
    ToolRegistry,
    load_policy,
)

registry = ToolRegistry()
registry.register_read("inventory.available", check_inventory)
registry.register_target("commerce.place_order", place_order)

engine = GatewayEngine(
    load_policy("private-workflow.json"),
    registry=registry,
    notifier=trusted_notifier,
    approval_verifier=trusted_out_of_band_verifier,
    execution_authority=ExecutionAuthority("production-host"),
)
```

A consumer should keep credentials, private targets and environment-specific
policy in its own repository. Only genericized mock examples belong here.

## Trust boundary

Agent-callable MCP methods may create, inspect or cancel requests. They cannot:

- ingest trusted approval;
- register a tool;
- change policy;
- create execution authority;
- invoke an effectful target directly.

The host process owns those capabilities. See [SECURITY.md](SECURITY.md) and
[ARCHITECTURE.md](ARCHITECTURE.md).

The stdio MCP process also receives its principal and trusted context from host
launch configuration. `request_action` has no `requester` or `trusted_context`
argument, so a model cannot impersonate another agent or assert that a trusted
precondition is true.

## Public-readiness

This repository is intentionally self-contained and uses no runtime dependencies.
Examples contain placeholders only—no live URLs, credentials, account names,
machine paths or private integration identifiers. Private consumers should keep
their adapters private and contribute only generalized, simulation-only examples.

## License

MIT
