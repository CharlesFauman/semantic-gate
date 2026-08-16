# Multi-step flows

Semantic Gate is a permission plane, not an orchestrator. **Agent owns the flow
between actions**: planning, order, branching, retries, compensation, stopping
and whether to propose each next semantic action remain outside the gate. For a
single request, trusted approval ingestion currently advances synchronously
through rechecks and simulation/target invocation.

## Run the multi-step example

```sh
PYTHONPATH=src python examples/integrations/multi_step_flow.py
```

Expected result:

```json
{"agent_owned_flow":true,"events":["build_waiting","build_simulated","publish_waiting","publish_simulated"],"execution_enabled":false,"final_state":"simulated","notifications":2,"ok":true,"separate_request_ids":true}
```

The script runs the real coordinator for two independent semantic actions:

1. `release.build` — private write requiring ordinary approval.
2. `release.publish` — external write requiring step-up approval.

Each action gets a different request ID, hash, notification, evidence and
decision. The agent chooses whether step 2 should exist only after observing
step 1's result. Both bundled example actions end in `simulated`, so no target
is invoked. In enforcing mode, approval ingestion for each individual request
would immediately advance through rechecks and call that request's registered
target; the agent still controls whether to propose the next action.

## Conceptual orchestration pseudocode

The runnable example uses dictionaries returned by the coordinator; a real
orchestrator would poll or receive state changes through its own workflow layer:

```python
build = gate.request_action(
    action="release.build",
    parameters=build_parameters,
    context={}, trusted_context={}, requester="example-agent",
    idempotency_key="build-v1",
)
# Human decision arrives through a host-only surface.
build = gate.get_request(build["request_id"])

if build["state"] not in {"simulated", "executed"}:
    return "stop"
if source_changed_since(build["request_hash"]):
    return "discard stale approval"

# The agent decides to continue; Semantic Gate did not schedule this.
publish = gate.request_action(
    action="release.publish",
    parameters=publish_parameters,
    context={}, trusted_context={}, requester="example-agent",
    idempotency_key="publish-v1",
)
```

## Branching and retries

- A failed precondition should block only that request.
- A denied build should prevent the agent from proposing publish.
- An expired publish approval can be abandoned or reproposed with a new exact request.
- Reusing an idempotency key with changed parameters fails.
- A transient notifier outage may retry notification delivery according to host policy, but must not manufacture approval.
- An agent may stop before proposing the next action. It cannot pause a current
  request between approval ingestion and target invocation in the bundled v0.2
  engine.

## Compensation

Compensation is another semantic action, not an implicit rollback bypass. For example:

```text
release.publish (succeeds)
  → health check fails
  → agent proposes release.rollback with exact current/target versions
  → policy requires its own approval and rechecks
```

Do not give a compensation action broader credentials than the original operation. Bind it to exact before/after versions and verify the final state.

## Unknown outcome

If a broker times out after sending an effectful request, the outcome may be unknown. Do not automatically retry. The agent should:

1. query the downstream system through a scoped read;
2. reconcile using the operation's idempotency key or receipt;
3. classify the result as succeeded, failed or still unknown;
4. propose a retry or compensation only when policy and target semantics make that safe.

## Long-running workflows

Store workflow state in the orchestrator, not in approval evidence. A later step should reference exact immutable artifacts/receipts from earlier steps. Recheck mutable state at each permission boundary. Semantic Gate can authorize each edge without owning the graph.
