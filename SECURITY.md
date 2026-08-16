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
9. Approval evidence is request-, gate- and evidence-ID-bound and expiring.
   Version-2 approval issues a separate signed authorization and performs no
   target call.
10. Every enforcing approval must have a recheck descendant on the execute path.
11. Enforcing mode rejects undelivered or misbound notification evidence.
12. Read evidence tools and effectful target tools use separate registries.
13. Live execution requires signed authorization, enforcing policy, a
    non-simulated exact target, and broker-owned execution authority.
14. Authorization consumption is durably reserved before target invocation;
    replay is rejected across restart.
15. Timeouts and interrupted consumption become `unknown` and are never
    automatically retried; explicit reconciliation is required.
16. Default MCP construction trusts no approval evidence and has no authority.
17. The caller never selects permission mode. `minimum_control` may only raise
    the effective approval requirement; policy remains authoritative and the
    floor is request-hash/idempotency bound.
18. Approval levels are closed to ordinary `ask` and `step_up`. Signed evidence
    carries assurance and the engine rejects evidence below the effective
    request control. The bundled password panel provides ordinary assurance;
    deployments must use an independently authenticated stronger transport for
    step-up.

## Host responsibilities

A production host must:

- authenticate agents and set an unforgeable requester identity;
- inject security-relevant context from the authenticated transport rather than model arguments;
- keep target credentials outside agent environments;
- ensure agents cannot bypass the gateway by accessing raw target tools;
- implement a notifier that provides truthful delivery evidence;
- verify human approval through an independent authenticated surface;
- bind approval to request hash, actor, decision and expiry;
- use the bundled durable request-idempotency and authorization stores or an
  equivalent transactional implementation;
- protect against duplicate execution at the downstream adapter too;
- redact sensitive parameters from logs and user-facing notifications;
- constrain target adapter egress and credentials to least privilege;
- audit policy and adapter changes.

## Beta components

The optional service supplies durable request snapshots, audit metadata,
proposal-only REST/HTTP MCP, a simulation control panel, capability-derived
principals, signed deferred authorization, crash-aware broker state, Ed25519
human approval, and strict declarative downstream MCP mappings. These do not
turn the package into an operating-system sandbox or credential vault.

The browser panel requires an exact configured Origin plus a session-bound CSRF
token for every decision/control mutation. Secure cookies are the default;
private HTTP deployments must explicitly opt out and rely on a trusted private
transport until TLS is available. The service applies strict finite/bounded JSON
validation to HTTP and MCP bodies and emits no CORS policy.

## What the library does not provide

- distributed consensus or locks across coordinator replicas;
- built-in notification provider;
- secret storage;
- process/container isolation;
- formal verification of arbitrary adapter code.

The bundled store survives restart and classifies interrupted execution as
unknown, but cannot prove whether an external target committed before a crash.
Do not claim exactly-once external effects without downstream idempotency and a
reconciliation read/receipt.

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

## Supported versions

| Version | Security support |
|---|---|
| `0.3.0b1` | Current beta |
| `0.2.x` | Security maintenance during beta |
| `< 0.2` | Not supported |

Security fixes target the current beta/default branch and latest `0.2.x` patch.
Users should upgrade to the newest patch before reporting a regression.

## Reporting vulnerabilities

Do not open a public issue for a suspected vulnerability. Use GitHub’s private
[Report a vulnerability](../../security/advisories/new) route for this
repository. Include the affected version, impact, minimal reproduction and any
suggested mitigation, but do not include live credentials or private deployment
data. If the private advisory form is unavailable, contact a repository
maintainer through the private account/channel that granted repository access.
