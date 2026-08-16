# Changelog

## 0.3.0b1

### Deferred authorization

- Version 2 approval issues signed, durable authorization and never calls a target.
- Callers independently choose authorization consumption time.
- SQLite consumption is single-use across restart with unknown-outcome reconciliation.
- Durable coordinator request-idempotency binding survives restart.

### Integrations

- Strict declarative downstream MCP adapter host and validation CLI.
- Fixed command/tool mapping with minimal passed environment.
- Real Ed25519 human approval roster, host-only bridge and signer CLI.
- Optional Ed25519 authorization signer/public-only broker verifier.

### Compatibility

- Version 1 inline advancement remains deprecated compatibility during beta.
- Generated policies and bundled workflows default to version 2.

### Release quality

- Python 3.9/3.11/3.13 core matrix.
- Crypto-extra tests.
- Wheel build/install and source/installed runnable-example gates.

## 0.2.0

- Policy-owned approval floors and proposal-only MCP/HTTP surfaces.
- Durable request snapshots, audit observations and distributed node leases.
