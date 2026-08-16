# Buzz integration

In production, this integration uses Buzz as an independently signed human
approval surface. Buzz carries the review request and reaction; a trusted host
adapter must cryptographically verify both events before Semantic Gate sees an
authenticated signer. Semantic Gate remains the permission authority.
**Buzz does not execute** the target, choose control, or advance the agent workflow.

## Run the complete example

```sh
PYTHONPATH=src python examples/integrations/buzz_approval_flow.py
```

Expected result:

```json
{"authorization_consumed":false,"authorization_issued":true,"buzz_signature_verification_implemented":false,"effective_control":"step_up","execution_enabled":false,"ok":true,"state":"authorized","trusted_reaction_accepted":true,"untrusted_reaction_rejected":true,"verified_transport_boundary":true}
```

The script uses the real `build_policy`, `CoreBackend`, request hashing,
notification binding, approval assurance, expiry and replay protections.
`UnsignedBuzzTransportStub` is deliberately **not** a Buzz cryptographic
implementation. It makes the post-verification interface runnable offline. A
production adapter must replace notification posting, reaction retrieval,
event/reaction signature verification, signer enrollment and freshness checks.
Only then may it return `transport_verified=true` reactions to the bridge.

## End-to-end sequence

```text
Agent
  │ request_action(action, exact parameters, minimum_control?)
  ▼
Semantic Gate
  │ validates principal, closed schema and policy precheck
  │ derives policy control; caller floor may only increase it
  ▼
Buzz notifier
  │ posts a safe review event
  │ returns event ID bound to request ID/hash, gate, recipient and template
  ▼
Human owner
  │ adds exact signed 👍 reaction to that exact event
  ▼
Host approval bridge
  │ accepts only adapter-verified events/reactions
  │ checks event ID, emoji, enrolled signer, freshness, expiry, pending request
  │ submits signed assurance=step_up evidence to the host-only approval API
  ▼
Semantic Gate
  │ consumes evidence once, rechecks mutable conditions
  │ issues signed, durable authorization; no target call
  ▼
Agent
  │ independently decides whether/when to consume or abandon authorization
  ▼
Fixed broker
  │ atomically reserves, rechecks, then simulates or calls exact target
```

## Exact bindings

A production bridge should verify all of these before approval ingestion:

| Binding | Purpose |
|---|---|
| Notification event ID | Reaction belongs to the exact gate-created review message |
| Request ID and canonical request hash | No parameter or target substitution |
| Approval-gate ID | Evidence cannot satisfy another gate |
| Exact emoji | Avoid ambiguous free-form replies |
| Cryptographically verified signer public key | Never trust a caller-supplied label; only enrolled human owners count |
| Reaction timestamp/freshness | A valid old reaction cannot authorize a new request |
| Assurance | Ordinary evidence cannot satisfy `step_up` |
| Expiry | Old reactions cannot authorize current work |
| Evidence ID | Replay is rejected |

The review message should contain only safe, bounded fields. Keep credentials, raw prompts, command text, private file contents and unrestricted outputs out of Buzz and audit projections.

## Production adapter shape

1. The notifier sends through a dedicated Buzz service identity and verifies
   the relay/SDK result before recording the signed event ID.
2. A Buzz adapter retrieves events/reactions for unresolved notifications and
   verifies canonical event bytes, signatures, event linkage and timestamps.
3. A host identity registry maps the verified public key to an enrolled human;
   display names or payload signer strings are never authority.
4. The bridge checks exact reaction, pending request and expiry, then calls a
   host-only approval-ingestion method absent from agent MCP.
5. The target credential stays behind a separate broker. The agent must not
   retain a raw API/MCP/CLI path around it.

A signed chat service identity is not a human approver. Agent, notifier and bridge keys must never appear in the human allowlist.

## Failure handling

- Missing/failed notification: request does not become approvable.
- Wrong emoji or signer: ignore and audit the rejection.
- Expired or rebound evidence: fail closed.
- Duplicate reaction: evidence ID/replay protection prevents reuse.
- Buzz unavailable: leave the request pending; do not infer approval.
- Before approval ingestion, the request can be denied, cancelled or allowed to
  expire. After approval, the issued authorization can still be cancelled or
  abandoned before broker consumption.
- Broker returns an unknown outcome: do not automatically retry; reconcile target state first.

For a real integration, retain canonical audit data independently of Buzz. Human-facing Buzz messages are a projection, not the authoritative ledger.
