# Architecture

## Components

### Workflow policy

A policy maps a semantic action to:

- an allowlist of host-authenticated principals;
- a closed parameter schema;
- a named target tool;
- a directed acyclic graph of gates.

In v0.1, object and array parameters are opaque JSON values. Recursive nested
schemas are intentionally not implemented; adapters must validate their
domain-specific nested structures before producing evidence or effects.

Supported gates:

| Kind | Purpose |
|---|---|
| `schema` | Validate and normalize the exact request parameters |
| `condition` | Compare a deterministic request/context value |
| `tool` | Call a host-registered read-only precondition tool and test its result |
| `notify` | Call the host notifier and retain delivery evidence |
| `approval` | Stop until host-verified, exact request-bound evidence arrives |
| `execute` | Version 2: issue target-bound authorization; version 1: deprecated inline simulation/execution |

Every execute node is statically required to have notification and approval in
its ancestor graph. Cycles, unknown dependencies and undeclared fields fail at
policy load time.

### Gate engine

`GatewayEngine` owns the request state machine:

```text
processing
  ├─ blocked
  ├─ waiting_for_approval
  ├─ authorized
  ├─ simulated
  ├─ executed
  ├─ failed
  └─ cancelled
```

A request contains a canonical SHA-256 hash over action, parameters, context,
trusted host context, requester, idempotency key and the complete workflow.
Idempotency keys are therefore bound to one exact request and cannot be reused
for a materially different proposal. The coordinator persists that binding.

Agent-supplied `context` and host-supplied `trusted_context` are separate. Gate
conditions may inspect either, but any fact that grants power should use
`trusted_context`. The stdio MCP host injects both the principal and trusted
context; neither is an argument to the agent-callable request tool.

### Tool registry

The host registers tools into separate namespaces:

- `register_read` for evidence/precondition tools;
- `register_target` for effectful actions.

Policy cannot register a function. An agent cannot register a function through
MCP. A gate of kind `tool` can only call the read namespace; an execute gate can
only call the target namespace.

### Notification adapter

The notifier is host-provided. Its result becomes gate evidence. The bundled
`RecordingNotifier` is intentionally in-memory and returns `delivered: false`.
It is for dry runs and tests, not proof that a human was notified.

### Approval verifier

Approval enters through `GatewayEngine.ingest_trusted_approval`, which is not an
MCP tool. The engine independently checks:

- decision is `approve`;
- request ID and request hash match;
- approval gate ID matches the currently waiting gate;
- evidence ID is non-empty and has never been consumed in this process;
- actor is present;
- expiry is a future integer within the gate's configured TTL;
- host verifier accepts the evidence;
- request is currently waiting and evidence has not been consumed.

Notification evidence is likewise bound to request ID/hash, notification gate,
configured recipient, template hash, delivery time and a unique notification ID.
Enforcing mode rejects simulated, undelivered, stale/misbound or reused evidence.

The MCP server uses `DenyAllApprovalVerifier`.

### Deferred authorization and execution authority

For version 2, approval plus post-approval rechecks produce a signed token. The
engine does not hold target credentials and does not call the target. An
`AuthorizationBroker` with the addressed verification key, durable store, fixed
action map and host-owned `ExecutionAuthority` consumes later.

This is intentional separation of duties:

```text
checked-in policy permits execution
AND signed authorization matches broker audience/action/target/parameters/policy
AND broker atomically reserves an unconsumed, unexpired token
AND consumption-time recheck passes
AND broker fixed-map owns the exact target
AND trusted approval was ingested out of band
AND broker host supplied execution authority
```

### Coordinator service and durable projection

The optional coordinator wraps the engine with host-authenticated principals,
SQLite snapshots/audit metadata, emergency pause/revocation controls, REST,
HTTP MCP and a human simulation-review panel. Requester identity and trusted
context are derived by the host transport, not accepted from tool arguments.

Pending approvals expire on coordinator restart. Authorized requests and
request-idempotency bindings remain durable. Broker consumption transitions
`issued → executing` transactionally; startup recovery changes interrupted
`executing` rows to `unknown`, which requires explicit reconciliation.

### Distributed nodes and plugins

The coordinator is the policy decision point. A node broker is a policy
enforcement point on the machine or network that owns a capability. Signed
leases bind a request to one node, plugin, action, parameter hash, policy hash,
expiry and nonce. Brokers consume leases before execution and never retry a
target automatically.

Plugins expose semantic operations. The generic recipe plugin intentionally
cannot accept shell commands, script text, GUI coordinates or arbitrary
keystrokes. Local and remote effects therefore use the same workflow while
retaining OS-level and network-level least privilege.

## MCP boundary

The dependency-free stdio server implements the MCP JSON-RPC methods needed for
initialization, tool discovery and tool calls. Its agent-facing surface contains
proposal/status/cancellation only. Host approval and execution capabilities are
not serializable over that interface.

## Adapting downstream MCP tools

A host can map downstream MCP calls declaratively:

```python
host = DeclarativeAdapterHost("adapter-host.json", environment=secret_environment)
host.start()
broker = AuthorizationBroker(
    broker_id="reviewed-broker",
    authority=public_authorization_verifier,
    store=authorization_store,
    execution_authority=ExecutionAuthority("reviewed-host"),
    revocation_checker=current_authorization_is_active,
    expected_policy_hash=engine.policy_hash,
    actions=host.broker_actions(),
    clock=clock,
)
```

Commands and tool names are fixed in checked-in config; only explicitly named
environment variables reach each subprocess. Remove the raw effectful MCP and
credentials from the agent before calling an action enforced.
