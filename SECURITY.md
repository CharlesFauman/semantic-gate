# Security model

Semantic Gate is a policy enforcement component, not a complete sandbox.
Security depends on correct host integration and on agents being denied direct
access to the downstream effectful tools that Semantic Gate is meant to gate.

## Invariants

1. Unknown actions and parameters fail closed.
2. The host supplies requester identity; the MCP caller cannot override it.
3. Trusted context is host-injected and separate from agent context.
4. Principal allowlists are checked before any gate or notifier runs.
5. Policy is immutable through the MCP surface.
6. Approval ingestion is never exposed as an MCP tool.
7. Execution is never exposed as an MCP tool.
8. Every approval depends on notification; every execute depends on both.
9. Approval evidence is request-, gate- and evidence-ID-bound, TTL-bounded,
   expiring and single-use within one engine process.
10. Every enforcing approval must have a recheck descendant on the execute path.
11. Enforcing mode rejects undelivered or misbound notification evidence.
12. Read evidence tools and effectful target tools use separate registries.
13. Live execution requires both enforcing policy and host-owned authority.
14. Target failures are terminal and are never automatically retried.
15. Default MCP construction trusts no approval evidence and has no authority.

## Host responsibilities

A production host must:

- authenticate agents and set an unforgeable requester identity;
- inject security-relevant context from the authenticated transport rather than model arguments;
- keep target credentials outside agent environments;
- ensure agents cannot bypass the gateway by accessing raw target tools;
- implement a notifier that provides truthful delivery evidence;
- verify human approval through an independent authenticated surface;
- bind approval to request hash, actor, decision and expiry;
- persist request/evidence state transactionally if restart safety matters;
- protect against duplicate execution at the downstream adapter too;
- redact sensitive parameters from logs and user-facing notifications;
- constrain target adapter egress and credentials to least privilege;
- audit policy and adapter changes.

## Additional v0.2 components

The optional service supplies durable request snapshots, audit metadata,
proposal-only REST/HTTP MCP, a simulation control panel, capability-derived
principals and distributed single-use execution leases. These additions do not
turn the package into an operating-system sandbox or credential vault.

The browser panel requires an exact configured Origin plus a session-bound CSRF
token for every decision/control mutation. Secure cookies are the default;
private HTTP deployments must explicitly opt out and rely on a trusted private
transport until TLS is available. The service applies strict finite/bounded JSON
validation to HTTP and MCP bodies and emits no CORS policy.

## What the library does not yet provide

- crash-resumable transactional engine state for live execution;
- distributed consensus or locks across coordinator replicas;
- built-in identity provider or biometric verification;
- built-in notification provider;
- built-in downstream MCP client;
- secret storage;
- process/container isolation;
- formal verification of arbitrary adapter code.

The bundled engine and coordinator are appropriate for design, tests,
simulation and single-process integration. The coordinator expires unresolved
requests after restart. Do not claim crash-safe exactly-once execution without
durable execution claims, adapter reconciliation and downstream idempotency.

## Deployment status language

- **Catalogued:** an action has schema and policy metadata.
- **Shadowed:** requests and audit pass through Semantic Gate, but another direct
  credential/tool/shell path can bypass it.
- **Enforced:** the agent has no direct downstream credential or raw effectful
  tool; the only execution path is an isolated broker/plugin.

Never describe a shadowed integration as protected or enforced.

Public JSON boundaries are intentionally bounded: signed 64-bit integers,
64 KiB strings, 10,000-item collections, depth 64, 100,000 nodes, 256-character
JSON-RPC string IDs and 1 MiB stdio messages. Hosts may impose tighter limits.

## Reporting vulnerabilities

While the repository is private, report issues directly to the repository owner.
Before public release, add a private GitHub security-advisory route and a
supported-version policy.
