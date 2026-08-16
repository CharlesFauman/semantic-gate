# Existing tools and MCP servers

Semantic Gate complements **Existing MCP servers** and ordinary tool APIs; it does not require rewriting them. The key design choice is which side of the trust boundary can call each tool.

## Run the adapter example

```sh
PYTHONPATH=src python examples/integrations/existing_mcp_adapter.py
```

Expected result:

```json
{"agent_facing_mcp_host":true,"approval_state":"authorized","authorization_consumed":true,"authorization_issued":true,"direct_agent_target_denied":true,"downstream_processes":2,"effectful_mcp_calls":0,"execution_authority_installed":true,"execution_enabled":false,"local_mock_only":false,"ok":true,"read_mcp_calls":3,"real_stdio_jsonrpc":true,"state":"simulated"}
```

The script uses a real `GatewayEngine`, `ToolRegistry`, gate DAG, notification
evidence, signed approval evidence, durable authorization and broker rechecks. It launches two
real line-delimited JSON-RPC stdio MCP subprocesses through the included
`StdioMCPClient`; there is no in-memory MCP stand-in.

For copy-paste installation and before/after agent configuration, see
[`examples/integrations/README.md`](../examples/integrations/README.md).

> Semantic Gate is not a transparent zero-config proxy. A trusted host must map
> exact downstream tools into read or target adapters, and the effectful MCP
> must be removed from the agent's direct configuration before the action is
> enforced.

## Recommended topology

```text
Agent MCP client
  └── Semantic Gate MCP
        ├── request/list/explain/status/cancel
        └── no approval or execution tool

Host process
  ├── read adapter ──► inventory MCP: inventory.available
  ├── notifier / approval verifier
  └── execution broker ──► orders MCP: orders.place
```

The agent can propose `order.place`; it cannot call `orders.place` through
Semantic Gate's MCP surface. The inventory query is a read-only precondition.
Approval issues authorization without a target call. When the agent later chooses consumption, the broker atomically reserves
the token and runs inventory a third time immediately before the effect. The
effectful target and its order credential exist only in that broker.

## Wrapping an existing MCP server

```python
adapter = DeclarativeAdapterHost("adapter-host.json", environment=host_secrets)
adapter.start()
registry = adapter.register_reads(ToolRegistry())
broker = AuthorizationBroker(
    broker_id="orders-broker",
    authority=public_authorization_verifier,
    store=authorization_store,
    execution_authority=ExecutionAuthority("orders-host"),
    revocation_checker=current_authorization_is_active,
    expected_policy_hash=engine.policy_hash,
    actions=adapter.broker_actions(),
    clock=clock,
)
```

This is only enforcement when the agent cannot also connect directly to `orders-mcp`. Move the effectful server credential or socket behind the host/broker and **remove the raw** effectful MCP from the agent's tool configuration. Otherwise the integration is merely catalogued or shadowed.

## Migration checklist

1. Inventory the existing MCP's tools and classify each exact operation.
2. Keep safe evidence queries as read adapters.
3. Register effectful operations as host-only target adapters.
4. Give the agent only Semantic Gate's proposal MCP.
5. Remove the original effectful MCP entry and credential from the agent.
6. Run in simulation/shadow mode and compare observations.
7. Prove an approved brokered request works and a direct unapproved request
   fails before marking that action enforced.

## Integration options

### Sidecar gateway

Run Semantic Gate beside an existing agent. Expose proposal-only HTTP/MCP to the agent and let the sidecar call downstream MCP servers with host-owned credentials.

### In-process library

Embed `GatewayEngine` and `ToolRegistry` in the application that already owns downstream clients. This gives the smallest trust boundary.

### Distributed node broker

Issue an expiring, single-use lease addressed to the exact node, plugin, action and parameter hash. `NodeBroker` validates and consumes the lease before invoking a fixed plugin.

### Observation-only migration

Add content-free attempted/completed observations around the existing path first. Observation shows coverage but does not block bypasses. Promote an action only after the broker owns its credential/effect and the direct agent path fails.

## Adapter requirements

- Closed parameter schema; reject unknown fields.
- No caller-selected command, script, MCP server or tool name.
- Exact target allowlist.
- Separate read and effectful registries.
- Bounded timeouts and outputs.
- Target idempotency key or reconciliation strategy.
- Post-approval recheck for mutable conditions.
- No automatic retry after an unknown target outcome.
- Credentials removed from agent environments.

Semantic Gate asserts the deterministic permission path. The host still owns transport authentication, tool registration, credential isolation and downstream reconciliation; see [ASSERTIONS.md](ASSERTIONS.md).
