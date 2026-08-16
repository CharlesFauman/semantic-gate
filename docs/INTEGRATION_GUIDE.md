# Integration guide

Semantic Gate is a permission plane for semantic actions, not an agent workflow
engine. Version-2 policies keep proposal, policy evaluation, human evidence,
authorization and target consumption distinct. Approval ends at `authorized`;
the caller separately decides whether and when to submit the signed token to a
fixed broker.

## Choose an integration option

| Option | Best for | Authority |
|---|---|---|
| Direct Python SDK | Python applications and services | Proposal/read only unless the host separately supplies approval/execution authority |
| HTTP API | Language-neutral clients and mobile/backend facades | Bearer principal scopes proposal/read/observation routes |
| MCP | Agents using stdio or remote MCP | List, explain, propose, inspect and cancel only; no approval/execution tool |
| Content-free observer | Shadow/audit migration | Observation only; no proposal, approval or target authority |
| `RecipePlugin` | Fixed local commands with closed parameters | Consumes broker authorization; never accepts arbitrary shell text |
| `NodeBroker` | Remote/local node execution | Validates node/action/parameter-bound single-use lease before plugin invocation |

See `examples/integrations/` for minimal source examples.

## Policy decides; callers can only escalate

A caller supplies the semantic action and closed parameters. **Policy decides** the required control. The optional `minimum_control` field is a floor:

- `policy`: no caller escalation;
- `ask`: require at least ordinary human approval;
- `step_up`: require step-up approval evidence.

The effective requirement is the stricter of policy and caller floor. A caller cannot choose `allow`, lower a policy requirement or supply approval evidence through MCP. The floor is request-hash and idempotency bound.

`step_up` is not a label-only TTL change. Approval evidence includes signed
`assurance=step_up`, and the engine rejects ordinary `ask` assurance for an
effective step-up request. The bundled password panel intentionally provides
only ordinary assurance; connect WebAuthn, a separately authenticated signed
human channel, quorum, or another reviewed stronger transport for step-up.

## Approval issues permission; it does not execute

For a version-2 policy, trusted approval ingestion runs mandatory post-approval
checks and issues a signed authorization bound to request, action, target,
parameters, policy, approval evidence, audience and expiry. It performs no
target call. The requester may abandon or cancel the authorization, or later submit its
non-secret ID to the addressed broker.

The broker loads and atomically reserves the host-stored record in SQLite, performs another mutable
state recheck, and only then simulates or calls its fixed target. A repeated
record is rejected across process restart. A timeout or ambiguous post-dispatch
failure becomes `unknown`. A crashed process leaves `executing` reserved until
an operator confirms abandonment and explicitly recovers it to `unknown`; that
state requires explicit reconciliation and no state is automatically retried.
Approval remains host-only and absent from agent MCP.

Version-1 policies retain deprecated inline advancement solely for migration.
New integrations should use version 2.

## Direct Python SDK

Use `SemanticGateClient` with a host-issued principal capability. Omit `minimum_control` for policy ownership or set a stricter floor. The SDK exposes list/get/request/cancel and content-free observation methods.

## HTTP API

The API supports action discovery, proposals, owned-request reads/cancellation and observer ingestion. Authenticate the principal at the host boundary. Never accept requester identity or trusted context from the caller.

## MCP

Both stdio MCP and the coordinator's remote MCP expose the same proposal-only model. Agents cannot approve, mutate policy or execute. Hosts inject principal and trusted context.

## Content-free observer

Observer principals submit normalized operation labels, phase/outcome, node/harness and opaque correlation IDs. Do not send arguments, commands, prompts, bodies, file contents, outputs, paths, search terms or credentials. Observation proves coverage, not enforcement.

## Fixed recipe integration

`RecipePlugin` requires an absolute reviewed executable, exact placeholder set, allowlisted parameter values, bounded timeout and minimal environment. Do not expose arbitrary shell, AppleScript/PowerShell text, browser scripts, GUI coordinates or keystrokes.

## Node broker integration

A `NodeBroker` validates the signed lease audience, node, plugin, action, canonical parameter hash, expiry, nonce and single-use state before calling a plugin. Offline nodes do not queue surprise work; expired authorization is discarded.

## Per-action migration

Migrate one action at a time:

1. catalogue exact action and closed schema;
2. observe existing path without changing outcome;
3. implement reviewed adapter;
4. move target credential/effect authority behind adapter;
5. verify approved brokered success;
6. verify direct unapproved agent attempt is denied;
7. test pause, revocation, stale state and unknown outcome;
8. mark only that action enforced.

Remove a shared workaround path only after every dependent action is enforced.

## Git fetch/pull/push example

`examples/integrations/git-actions.json` shows a generalized Git integration.
It deliberately separates fetch (read/audit), pull (local private write/ask) and
push (remote external write/step-up). Each action binds a repository ID, remote,
ref/refspec, expected before commits and verified after commits. A production
broker should own the remote credential, forbid arbitrary Git subcommands and
emit action-specific attempted/completed observations. Do not mark one Git
action enforced merely because another uses a broker.

## Integration patterns

- Git providers: broker exact repository/ref/PR operations; keep merge/deploy credentials out of agents.
- Cloud control: broker exact project/environment/resource operations and source digests; never place secret values in proposals.
- Home automation: expose fixed entity/service recipes, not arbitrary service calls.
- Messaging/email: bind exact sender identity and destination; keep message bodies out of projection.
- Browser/desktop: prefer isolated sessions and fixed reviewed flows; preserve OS/browser permission boundaries.
- Mobile: retain on-device permission and secure-enclave boundaries; host approval cannot impersonate the device.

## Private deployment boundary

Keep generic workflow, engine, SDK, MCP, broker and plugin abstractions in this repository. Private consumers should keep real identities, hosts, IPs, credentials, action catalogues, node assignments, service wiring and migration state in their own repository. Private integrations can publish generalized examples here after removing deployment assumptions and identifiers.

## Production checklist

- policy and action schema reviewed;
- caller cannot downgrade control;
- approval surface independently authenticated;
- approval evidence assurance matches required level;
- adapter owns credential/effect;
- raw bypass denied;
- request/authorization replay protected across the required lifetime;
- coordinator request idempotency persists across restart;
- broker authorization consumption and replay state persist across restart;
- unknown outcomes have an operator reconciliation procedure;
- post-approval mutable state rechecked;
- target idempotency or reconciliation defined;
- no automatic retry after unknown outcome;
- pause/revoke tested;
- audit content bounded and non-sensitive.
