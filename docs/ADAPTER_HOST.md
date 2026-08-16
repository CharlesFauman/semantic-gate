# Declarative downstream MCP adapter host

Semantic Gate does not automatically proxy arbitrary MCP tools. `DeclarativeAdapterHost` loads a closed config that fixes downstream commands, read mappings and action targets.

Validate a file without launching downstream processes:

```sh
semantic-gate-adapter-check --config adapter-host.json
```

## Shape

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
    "inventory.available": {"server": "inventory", "tool": "inventory.available"}
  },
  "actions": {
    "order.place": {
      "target": "orders.place",
      "server": "orders",
      "tool": "orders.place",
      "recheck_read": "inventory.available",
      "outcome": "reconcilable"
    }
  }
}
```

The executable must be absolute. No shell is used. Only variables named by `pass_environment` reach each child; the host does not inherit the full credential environment. The caller cannot select a command, server, tool or target.

Every action declares `outcome` as `idempotent` or `reconcilable`. Idempotent
actions must name an `idempotency_field` present in authorized parameters;
reconcilable actions require a downstream status/receipt procedure.
After target dispatch, every exception—including EOF, malformed response,
process exit, timeout or receipt-persistence failure—is treated as `unknown`.
It is never converted to a retryable failure.

`broker_actions()` produces the fixed map accepted by `AuthorizationBroker`. The broker verifies audience/action/target/parameter/policy bindings, reserves the token durably, rechecks through the declared read, and then calls the fixed target.

Every broker also requires a fail-closed `revocation_checker`. A local broker can
consult the shared authorization store; a distributed broker must query or
replicate coordinator status. If status is unavailable, consumption is denied.
It also requires `expected_policy_hash` for the exact currently reviewed policy;
tokens from any other policy revision are rejected before reservation.

An integration remains shadowed while the agent can still reach the original effectful MCP or its credentials.
