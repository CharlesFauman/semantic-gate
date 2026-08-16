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
| `execute` | Simulate or call the host-registered target after all dependencies pass |

Every execute node is statically required to have notification and approval in
its ancestor graph. Cycles, unknown dependencies and undeclared fields fail at
policy load time.

### Gate engine

`GatewayEngine` owns the request state machine:

```text
processing
  ├─ blocked
  ├─ waiting_for_approval
  ├─ simulated
  ├─ executed
  ├─ failed
  └─ cancelled
```

A request contains a canonical SHA-256 hash over action, parameters, context,
trusted host context, requester, idempotency key and the complete workflow.
Idempotency keys are therefore bound to one exact request and cannot be reused
for a materially different proposal.

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

### Execution authority

An enforcing policy is not enough. The embedding host must also instantiate and
pass an `ExecutionAuthority`. The default MCP builder never does this.

This is intentional separation of duties:

```text
checked-in policy permits execution
AND host process enables execution mode
AND host registered the exact target
AND trusted approval was ingested out of band
AND all current preconditions pass
AND host supplied execution authority
```

## MCP boundary

The dependency-free stdio server implements the MCP JSON-RPC methods needed for
initialization, tool discovery and tool calls. Its agent-facing surface contains
proposal/status/cancellation only. Host approval and execution capabilities are
not serializable over that interface.

## Adapting downstream MCP tools

A host can wrap a downstream MCP client call inside a registered callable:

```python
registry.register_read("crm.customer_exists", lambda args: downstream.call("customer_exists", args))
registry.register_target("crm.create_ticket", lambda args: downstream.call("create_ticket", args))
```

Keep the downstream client and credentials outside the agent-facing process when
stronger isolation is required. Semantic Gate's registry is an interface, not a
credential vault or process sandbox.
