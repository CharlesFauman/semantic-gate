# Assertions and trust boundaries

This page distinguishes library guarantees from deployment responsibilities. A useful gate is explicit about both.

## Semantic Gate asserts

For accepted policy and host inputs, the core validates that:

- action and parameter schemas are closed and bounded;
- the host-authenticated principal is allowed for the action;
- caller context cannot replace trusted host context;
- policy—not the caller—selects required control;
- `minimum_control` can only raise the requirement;
- gate dependencies are valid, acyclic and deterministic;
- execution depends on notification and approval;
- notification evidence binds request ID/hash, gate, recipient and template;
- approval evidence binds request ID/hash, approval gate, evidence ID, actor, assurance and expiry;
- approval evidence is consumed once in the engine process;
- enforcing workflows recheck mutable conditions after approval;
- read tools and effectful target tools occupy separate registries;
- live target invocation requires both enforcing policy and host-owned execution authority;
- agent-callable MCP has no approval-ingestion or execution method.

## Host must assert

The embedding host is responsible for:

- authenticating the real caller and human approver;
- injecting trustworthy node, user-presence and environment context;
- registering only reviewed tools/adapters;
- protecting notifier and approval-signing identities;
- keeping target credentials out of agent reach;
- removing direct shell/API/MCP/GUI bypasses;
- making target operations idempotent or reconcilable;
- persisting replay/idempotency state for the required restart lifetime;
- bounding network egress, subprocesses and outputs;
- recording canonical audit state independently of chat projections;
- verifying postconditions and unknown outcomes.

## Semantic Gate does not assert

The library does not claim that:

- prompts or model instructions are a security boundary;
- a notification was seen by a human merely because an API returned success;
- a public key belongs to the intended person without host enrollment;
- arbitrary adapter code is safe;
- a downstream API completed when its response was lost;
- process-local idempotency survives restart;
- an agent cannot bypass the gate while it still holds raw credentials/tools;
- simulation approval executed anything;
- observation-only hooks enforce permission;
- the bundled coordinator provides distributed consensus or crash-safe exactly-once execution.

## Status language

- **Catalogued:** action/schema/policy exist.
- **Shadowed:** gate/audit path exists, but a direct bypass remains.
- **Enforced:** the reviewed broker is the only effect path and direct unapproved access is technically denied.

Use these labels per action. One brokered operation does not make an entire MCP server, credential or domain enforced.
