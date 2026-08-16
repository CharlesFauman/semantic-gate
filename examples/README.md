# Examples

These examples demonstrate the same generic gate engine across unrelated domains:

- `calendar-booking/` — conflict and terms checks before notification and approval.
- `purchase-approval/` — inventory and budget checks, then approval and inventory recheck.
- `device-control/` — allowlisted target, safety check, approval and safety recheck.

Every checked-in example is `simulation_only` with execution disabled. Names,
providers and targets are placeholders. There are no live URLs, credentials or
environment-specific identifiers.

## Runnable integration flows

- `integrations/buzz_approval_flow.py` — verified-reaction adapter boundary and
  real step-up approval ingestion; Buzz cryptography is explicitly not bundled;
- `integrations/existing_mcp_adapter.py` — existing read/effect MCP tools behind
  the real engine registry;
- `integrations/multi_step_flow.py` — two separately authorized actions with
  agent-owned sequencing and branching.

Run them from the repository root:

```sh
PYTHONPATH=src python examples/integrations/buzz_approval_flow.py
PYTHONPATH=src python examples/integrations/existing_mcp_adapter.py
PYTHONPATH=src python examples/integrations/multi_step_flow.py
```

## Adapting a private integration

Keep private policy and adapter code in the consuming repository. Use the public
concepts here without copying private details back into this repository:

```python
from semantic_gate import GatewayEngine, ToolRegistry, RecordingNotifier
from semantic_gate.engine import load_policy

registry = ToolRegistry()
registry.register_read("calendar.no_conflict", my_read_only_conflict_check)
registry.register_target("calendar.create_event", my_effectful_calendar_adapter)

engine = GatewayEngine(
    load_policy("private/workflow.json"),
    registry=registry,
    notifier=my_trusted_notification_adapter,
    approval_verifier=my_out_of_band_approval_verifier,
    execution_authority=my_host_owned_execution_authority,
)
```

The agent-facing MCP never receives `my_out_of_band_approval_verifier` or
`my_host_owned_execution_authority`. A private adapter may call any API, local
service, MCP tool or operating-system integration, but Semantic Gate sees it only
as a named host-registered callable with a declared role:

- **read tool** — may produce precondition evidence;
- **notifier** — must return delivery evidence;
- **approval verifier** — accepts only exact, unexpired, request-bound evidence;
- **target tool** — effectful and unreachable until every gate has passed.

To publish a genericized example from a private integration:

1. replace people, hosts, devices, providers and accounts with placeholders;
2. remove URLs, credentials, tokens and filesystem paths;
3. use mock adapter functions;
4. keep the same gate shape and failure tests;
5. leave execution disabled.
