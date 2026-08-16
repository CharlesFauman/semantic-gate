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

Start with [`docs/QUICKSTART.md`](docs/QUICKSTART.md), then use
[`docs/INTEGRATION_GUIDE.md`](docs/INTEGRATION_GUIDE.md) for SDK, HTTP, MCP,
observer, fixed-recipe and node-broker options.

Beta references:

- [`docs/BETA.md`](docs/BETA.md) — acceptance criteria and non-claims;
- [`docs/MIGRATING_TO_0_3.md`](docs/MIGRATING_TO_0_3.md) — version-1 migration and rollback;
- [`docs/ED25519_APPROVALS.md`](docs/ED25519_APPROVALS.md) — enrolled public-key human approval;
- [`docs/ADAPTER_HOST.md`](docs/ADAPTER_HOST.md) — strict existing-MCP mappings.

### Learn by running

- [`docs/BUZZ_INTEGRATION.md`](docs/BUZZ_INTEGRATION.md) — Buzz verified-
  reaction boundary → host approval → recheck flow, with production signature
  responsibilities explicit.
- [`docs/EXISTING_TOOLS_AND_MCP.md`](docs/EXISTING_TOOLS_AND_MCP.md) — put
  existing MCP read tools and effectful targets on the correct side of the
  trust boundary.
- [`docs/MULTI_STEP_FLOWS.md`](docs/MULTI_STEP_FLOWS.md) — agent-owned
  branching, retries, compensation and unknown outcomes across separate
  permission requests.
- [`docs/ASSERTIONS.md`](docs/ASSERTIONS.md) — exact library guarantees,
  host responsibilities and non-guarantees.

Run the offline examples directly:

```sh
make example-buzz
make example-mcp
make example-mcp-host  # launches the agent-facing MCP host and calls it
make example-multistep
# or all runnable flows:
make examples
```

No installation is required for the Make targets. For a virtual-environment
install and existing-MCP before/after configuration, see
[`examples/integrations/README.md`](examples/integrations/README.md).

All default examples are simulation-only. After reviewing the trust-boundary
guide, `make example-mcp-enforcing-mock` is an explicit opt-in proof that invokes
only the bundled local mock target with a host-owned `ExecutionAuthority`; it
does not contact a real external system.

> **Status:** `0.3.0b1` beta. All default examples are simulation-only. Version-2
> policies separate approval from execution: approval issues a signed, durable,
> expiring authorization; a caller later chooses whether to submit its ID to a
> fixed broker. Version-1 inline execution remains deprecated compatibility only.

## Why

Prompt instructions such as “ask before buying” are useful guidance, but not a
security boundary. Semantic Gate turns that intent into a deterministic state
machine.

### What this helps with

| Problem | Semantic Gate's role |
|---|---|
| An agent is told to ask but can skip the prompt rule | Enforce a checked-in gate DAG outside the model |
| An existing MCP mixes reads and dangerous writes | Keep read-only preconditions visible while moving effectful tools behind a broker |
| Chat approval could apply to the wrong request | Bind identity, request hash, gate, assurance and expiry |
| One approval accidentally drives an entire multi-step workflow | Authorize each exact effect separately while the agent retains flow control |
| Audit hooks exist but raw credentials remain | Label the action shadowed until the direct bypass is removed and tested |
| Teams need stronger review for selected actions | Let callers escalate to `step_up` but never downgrade policy |

The library fits around existing tools, APIs and MCP servers; it does not require
replacing them. Its value is the explicit permission boundary and evidence model.

```text
normalize request
  → validate semantic schema
  → call read-only precondition tools
  → notify the human
  → wait for exact request-bound approval evidence
  → re-check time-sensitive conditions
  → issue durable signed authorization
  → caller independently chooses whether/when to consume
  → broker re-checks, atomically reserves authorization and calls fixed target
  → persist executed / failed / simulated / unknown outcome
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
- **Current schema scope:** scalar fields support bounds/enums; object and array
  fields are opaque JSON values rather than recursively validated.
- **Bounded JSON domain:** inputs reject non-string object keys, non-JSON
  Python values, excessive nesting/collections/strings, and integers outside
  the signed 64-bit range; stdio messages are capped at 1 MiB.
- **Gate DAGs:** dependencies are validated, cycle-free and deterministic.
- **Mandatory paths:** every execute node must depend on both notification and approval.
- **Out-of-band approval:** approval ingestion is a host API, never an agent-callable MCP tool.
- **Exact binding:** approval evidence is bound to request ID, request hash,
  approval-gate ID, unique evidence ID and expiry.
- **TOCTOU protection:** workflows recheck after approval before authorization;
  brokers recheck again immediately before target invocation.
- **Durable idempotency:** coordinator idempotency bindings survive restart and
  reject changed payload/context reuse.
- **Single-use consumption:** SQLite atomically transitions authorization from
  issued to executing before a target call; replay is rejected across restart.
- **Unknown outcomes:** interrupted or timed-out target calls become `unknown`
  and require explicit reconciliation rather than automatic retry.
- **Notification binding:** delivery evidence is bound to request ID/hash, gate,
  recipient, template hash, delivery time and a unique notification ID.
- **Separated tool roles:** read gates and effectful targets live in different registries.
- **Dual execution control:** live execution needs signed authorization, policy
  enablement, a non-simulated exact gate and a broker-owned `ExecutionAuthority`.
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
  "version": 2,
  "mode": "simulation_only",
  "execution_enabled": false,
  "authorization": {"audience":"example-broker","ttl_seconds":300},
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
- a mobile control panel for simulation review;
- SQLite request snapshots, audit events and emergency controls;
- durable request idempotency and signed authorization records;
- host-derived principal capabilities;
- redacted credential-binding inventory.

The coordinator requires distinct master, approval and authorization keys; see
the migration guide. `SemanticGateClient` provides the proposal contract without MCP. Local and
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
    AuthorizationBroker,
    ExecutionAuthority,
    GatewayEngine,
    SQLiteAuthorizationStore,
    ToolRegistry,
    load_policy,
)

registry = ToolRegistry()
registry.register_read("inventory.available", check_inventory)
store = SQLiteAuthorizationStore("authorization.sqlite3")

engine = GatewayEngine(
    load_policy("private-workflow.json"),
    registry=registry,
    notifier=trusted_notifier,
    approval_verifier=trusted_out_of_band_verifier,
    authorization_authority=private_authorization_signer,
    authorization_store=store,
)
broker = AuthorizationBroker(
    broker_id="commerce-broker",
    authority=public_authorization_verifier,
    store=store,
    execution_authority=ExecutionAuthority("production-host"),
    revocation_checker=current_authorization_is_active,
    expected_policy_hash=engine.policy_hash,
    actions=fixed_action_map,
    clock=clock,
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

The core is dependency-free; Ed25519 support is an optional `approvals` extra.
Examples contain placeholders only—no live URLs, credentials, account names,
machine paths or private integration identifiers. Private consumers should keep
their adapters private and contribute only generalized examples with no real effects.

## License

MIT
