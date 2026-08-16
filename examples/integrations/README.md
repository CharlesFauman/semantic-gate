# Runnable integrations

These examples use the real Semantic Gate engine/coordinator. They are offline,
dependency-free and simulation-only.

## Fastest path

From a clone, run without installing:

```sh
make examples
```

Or run one flow:

```sh
make example-buzz
make example-mcp
make example-mcp-host
make example-multistep
```

## Install in a virtual environment

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
make examples PYTHON=.venv/bin/python EXAMPLE_ENV=
```

This repository is not assumed to be published to a package index. `pip install
.` installs the checked-out source. Clearing `EXAMPLE_ENV` proves the examples
import that installed wheel rather than the repository's `src/` tree.

## Put Semantic Gate in front of an existing MCP

Semantic Gate is **not a transparent proxy** today. It does not discover an
arbitrary MCP server and safely gate every tool automatically. You classify
specific tools and register adapters in a trusted host process.

### Before: agent connects directly

```json
{
  "mcpServers": {
    "inventory": {"command": "inventory-mcp"},
    "orders": {"command": "orders-mcp"}
  }
}
```

In this layout the agent can call `orders.place` directly, so adding a separate
gate does not enforce anything.

### After: agent connects only to Semantic Gate (demo-only)

```json
{
  "mcpServers": {
    "semantic-gate": {
      "command": "/absolute/path/to/semantic-gate/.venv/bin/python",
      "args": [
        "/absolute/path/to/semantic-gate/examples/integrations/existing_mcp_adapter.py",
        "--serve"
      ]
    }
  }
}
```

That exact command is runnable after the virtual-environment installation above;
replace `/absolute/path/to/semantic-gate` with the clone's absolute path. It is
a **demo-only** replacement: it starts the two
bundled `example_downstream_mcp.py` processes. It does not automatically wrap
the `inventory-mcp` and `orders-mcp` commands shown in the “before” example.

`--serve` launches an agent-facing Semantic Gate MCP. Inside that trusted host
process, the demo registers one read adapter and one effectful target adapter.

### Production migration

Create a private, reviewed host based on `existing_mcp_adapter.py`:

1. Copy the host into the consuming repository; do not edit policy at runtime.
2. Replace both `example_downstream_mcp.py` command arrays in `build_host()`
   with fixed absolute commands for the real servers—no caller-selected command.
3. Replace `policy()` with checked-in exact actions, closed schemas, principals,
   approval levels and target mappings.
4. Replace `DeliveredNotifier` and the example approval key with authenticated
   notification, reaction/signature verification and host-secret loading.
5. Give the trusted host—not the agent—the downstream MCP credentials, sockets
   and environment. Keep broker credentials out of proposals and logs.
6. Keep the reviewed production policy at `mode="simulation_only"` while testing
   mappings and observations. Do not treat adapter registration as enforcement.
7. After credential isolation and deployment review, prepare—but do not yet
   expose—a host-owned `ExecutionAuthority`, set policy `mode="enforcing"` and
   `execution_enabled=true`, and set the exact execute gate
   `simulation_only=false`. Never expose the authority through MCP.
8. Remove the original effectful MCP entry and credential from the agent, then
   run the reviewed private host with `--serve` and point the agent only at it.
9. Prove approved brokered success and direct unapproved failure per action
   before calling that action enforced.

The resulting fixed adapter shape is:

```python
inventory = StdioMCPClient(["/absolute/reviewed/inventory-mcp"])
orders = StdioMCPClient(["/absolute/reviewed/orders-mcp"])

registry.register_read(
    "inventory.available",
    lambda args: inventory.call_tool("inventory.available", args),
)
registry.register_target(
    "orders.place",
    lambda args: orders.call_tool("orders.place", args),
)

# Only in the reviewed production host, after policy and credential isolation:
engine = GatewayEngine(
    load_policy("reviewed-production-policy.json"),
    registry=registry,
    notifier=trusted_notifier,
    approval_verifier=trusted_approval_verifier,
    execution_authority=ExecutionAuthority("reviewed-production-host"),
)
```

Then remove `orders-mcp` from the agent configuration and remove its credential
from the agent environment. If the direct connection remains, the action is
shadowed—not enforced.

`existing_mcp_adapter.py` demonstrates this shape with two real stdio JSON-RPC
MCP subprocesses:

```sh
make example-mcp
make example-mcp-host
```

`example-mcp` executes the full in-process host/approval simulation: inventory
runs twice (precheck and recheck), while the effectful orders MCP receives zero
calls. `example-mcp-host` launches the same file with `--serve`, connects as a
real MCP client, lists actions and submits a proposal that reaches
`waiting_for_approval`.

### Opt-in local enforcement proof

The ordinary examples stay simulation-only. To exercise the full execution
wiring without contacting a real service, run:

```sh
make example-mcp-enforcing-mock
```

This explicit local mock mode installs `ExecutionAuthority`, uses
`mode="enforcing"`, `execution_enabled=true` and `simulation_only=false`, proves
the agent-facing MCP cannot call `orders.place` directly, then submits exact
approval evidence and calls the bundled local orders MCP exactly once. Expected
result includes:

```json
{"direct_agent_target_denied":true,"effectful_mcp_calls":1,"execution_authority_installed":true,"execution_enabled":true,"local_mock_only":true,"state":"executed"}
```

Do not copy those enabling flags into a real deployment until its exact action,
adapter, credential isolation, veto/review and rollback path have been approved.

## Files

- `buzz_approval_flow.py` — real coordinator request, notification binding and
  step-up ingestion after an explicit transport-verification boundary; the
  offline stub does not implement Buzz signatures.
- `existing_mcp_adapter.py` — real engine plus real stdio JSON-RPC subprocesses.
- `mcp_host_smoke.py` — launches the agent-facing host command and calls it as
  an MCP client.
- `stdio_mcp_client.py` — minimal example-only MCP client.
- `example_downstream_mcp.py` — runnable example downstream MCP server.
- `multi_step_flow.py` — separate build/publish permission requests controlled
  by an agent-owned flow.

For production requirements and failure semantics, see:

- `../../docs/BUZZ_INTEGRATION.md`
- `../../docs/EXISTING_TOOLS_AND_MCP.md`
- `../../docs/MULTI_STEP_FLOWS.md`
- `../../docs/ASSERTIONS.md`
