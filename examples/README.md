# Examples

These examples demonstrate the same generic gate engine across unrelated domains:

- `calendar-booking/` — conflict and terms checks before notification and approval.
- `purchase-approval/` — inventory and budget checks, then approval and inventory recheck.
- `device-control/` — allowlisted target, safety check, approval and safety recheck.

Every default example is `simulation_only` with execution disabled. The only
opt-in enforcing path calls a bundled local mock. Names, providers and targets
are placeholders; there are no live URLs or credentials.

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
from semantic_gate.authorization import AuthorizationBroker
from semantic_gate.engine import load_policy

registry = ToolRegistry()
registry.register_read("calendar.no_conflict", my_read_only_conflict_check)


engine = GatewayEngine(
    load_policy("private/workflow.json"),
    registry=registry,
    notifier=my_trusted_notification_adapter,
    approval_verifier=my_out_of_band_approval_verifier,
    authorization_authority=my_private_signer,
    authorization_store=my_durable_store,
)

broker = AuthorizationBroker(
    broker_id="calendar-broker",
    authority=my_public_verifier,
    store=my_durable_store,
    execution_authority=my_host_owned_execution_authority,
    revocation_checker=current_authorization_is_active,
    expected_policy_hash=engine.policy_hash,
    actions=my_fixed_action_map,
    clock=clock,
)
```

The agent-facing MCP never receives approval signing or execution authority.
The engine sees read tools; the broker alone sees effectful targets and credentials.

- **read tool** — may produce precondition evidence;
- **notifier** — must return delivery evidence;
- **approval verifier** — accepts only exact, unexpired, request-bound evidence;
- **authorization signer** — issues exact, expiring broker permission;
- **target tool** — effectful and reachable only through broker consumption.

To publish a genericized example from a private integration:

1. replace people, hosts, devices, providers and accounts with placeholders;
2. remove URLs, credentials, tokens and filesystem paths;
3. use mock adapter functions;
4. keep the same gate shape and failure tests;
5. leave execution disabled.
