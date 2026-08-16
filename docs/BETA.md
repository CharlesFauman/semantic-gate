# Beta acceptance criteria

`0.3.0b1` is a beta because the reusable permission boundary is exercised end to end, while API feedback and production diversity are still expected before a stable `1.0` contract.

## Required properties

- Version 2 approval ends at durable `authorized`; it never invokes a target.
- Authorization is signed, audience-bound, parameter-bound, expiring and durably single-use.
- Public request snapshots expose authorization metadata/ID, never bearer signatures.
- Brokers require current non-revoked status; unavailable status denies consumption.
- Broker consumption performs another mutable-state recheck.
- Request idempotency and authorization replay protection survive restart.
- Unknown outcomes are durable and require reconciliation; no automatic retry.
- Effectful downstream MCP commands and credentials are fixed host configuration, not caller input.
- Agent MCP exposes proposal/status/cancel only—never approval, signing authority or direct execution.
- Ed25519 human approvals bind an enrolled public key, actor, request, assurance and time window.
- Default examples and coordinator policy remain simulation-only.

## Compatibility

- Version 2 is the beta default for generated policies and bundled examples.
- Version 1 remains supported as deprecated inline-execution compatibility during the beta series.
- `0.2.x` receives security maintenance while migrations are validated.

## Unknown outcomes

SQLite reserves authorization before target invocation. Timeouts and ambiguous
post-dispatch failures become `unknown`. A process crash leaves `executing`
durably intact; it is never swept at coordinator startup. After confirming the
broker attempt is no longer running, an operator explicitly runs
`semantic-gate-authorizations recover-interrupted` for that authorization ID,
then reconciles from a
downstream receipt or scoped read. Exactly-once external effects still require
downstream idempotency.

## Not claimed

Beta does not provide distributed consensus, a secret vault, process/container isolation, a notification provider, or formal verification of adapter code.
