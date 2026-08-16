# Migrating to 0.3 beta

This guide migrates version 1 policies to version 2. Version 1 policies approve and advance inline; Version 2 separates approval from execution through signed durable authorization.

## Policy migration

Change:

```json
{"version":1,"mode":"simulation_only","execution_enabled":false,"workflows":{}}
```

to:

```json
{
  "version":2,
  "mode":"simulation_only",
  "execution_enabled":false,
  "authorization":{"audience":"your-fixed-broker","ttl_seconds":300},
  "workflows":{}
}
```

Keep simulation enabled until the broker owns the target credential and direct agent access is denied.

## Coordinator secrets and storage

Add a distinct 32-byte hexadecimal key:

```sh
export SEMANTIC_GATE_AUTHORIZATION_KEY='<64 hex characters>'
```

Do not reuse the master capability key or approval key. The coordinator stores
authorizations and request idempotency in its SQLite database. On restart,
authorized requests survive; unresolved pending approvals remain durable but
must be explicitly cancelled and reproposed after process-local workflow state
is lost; `executing` consumption remains reserved. It is changed to `unknown` only by explicit
`semantic-gate-authorizations recover-interrupted` after an operator has
confirmed the broker attempt is no longer active. Then reconcile against a
scoped downstream read or receipt:

```sh
semantic-gate-authorizations recover-interrupted \
  --database semantic-gate.sqlite3 \
  --authorization-id auth_example --actor operator
semantic-gate-authorizations reconcile \
  --database semantic-gate.sqlite3 \
  --authorization-id auth_example --actor operator \
  --outcome executed --receipt-file verified-receipt.json
```

For distributed brokers, prefer `Ed25519AuthorizationAuthority` at the coordinator and distribute only `Ed25519AuthorizationVerifier` public keys.

## Caller changes

1. Propose and wait for human decision as before.
2. Expect `authorized`, not `simulated`/`executed`, after approval.
3. Decide whether and when to consume the returned authorization ID.
4. Submit only that ID to its declared audience broker.
5. Treat `unknown` as reconciliation-required, never retry permission.

## Broker changes

Use `AuthorizationBroker` plus `SQLiteAuthorizationStore`, a fixed action map, a
fail-closed revocation/status checker, a consumption-time recheck and
broker-owned `ExecutionAuthority`. Never select commands, tools or credentials
from token parameters. Callers submit authorization ID; signed bearer envelopes
remain in trusted storage.

## Rollback

Inspect outstanding authorization without exposing bearer signatures:

```sh
semantic-gate-authorizations list --database semantic-gate.sqlite3 --state issued
semantic-gate-authorizations list --database semantic-gate.sqlite3 --state executing
semantic-gate-authorizations list --database semantic-gate.sqlite3 --state unknown
```

Stop all brokers and the beta coordinator. Reconcile every `executing` or
`unknown` attempt from downstream state. Then revoke every still-unconsumed
authorization and verify none remain:

```sh
semantic-gate-authorizations revoke-issued \
  --database semantic-gate.sqlite3 --actor rollback-operator
semantic-gate-authorizations list --database semantic-gate.sqlite3 --state issued
```

Back up the database, restore the previous package/config, and keep version 1
policy simulation-only. Never roll back while an execution may still be active
or an unknown outcome is unreconciled.
