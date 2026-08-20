# Auto-approval examples

`global-simulation.json` is a generic, simulation-only auto-approval document.

- The standing `global_simulation_rule` is **automatic except communications and
  spending**: it auto-approves the approval gate for every catalogued
  non-prohibited action. It only applies while execution is disabled, and it
  never authorizes execution: `execution_enabled` remains a separate hard stop.
- Classification comes solely from the required `gate_class` field on each
  catalogue entry, one of exactly `automatic`, `human_communication`,
  `human_spending` or `prohibited`. Entries classified `human_communication`
  (communication, sending or disclosure to a person or external recipient) or
  `human_spending` (spending, transferring, purchasing or committing money)
  always keep the ordinary human gate; `prohibited` entries are not requestable
  at all. Action names and caller parameters never reclassify an entry, so an
  internal deploy or a read-only balance query classified `automatic` is
  auto-approved, and a harmless-looking name cannot smuggle a send or payment
  past the gate.
- The rule must declare `human_gate_classes` in full; a document can neither
  shrink nor extend it. Caller parameters can only fail a request toward the
  human gate (recursive secret, command and destructive-parameter screening
  through nested objects and arrays), never away from it.
- MCP and HTTP return a terminal simulated result for `automatic` entries in the
  same `request_action` call. External notifier delivery is deferred until after
  the bound policy decision and cannot gate it. The host binds each authenticated
  principal to its trusted `node`; caller context cannot choose that identity.
- `rules` holds scoped rules for the later execution-enabled promotion path. Each
  binds one canonical repository, exact refs, declared deploy target/environment,
  host-authenticated requesters/nodes, closed parameter constraints and a review
  date. Wildcards, near-match repository strings and path traversal fail to load.
- Placeholders only. Replace the requester, node and repository with your own
  host-authenticated identities in your private repository, and keep the review
  and expiry dates short enough that a human revisits them.

Pass the document to the bundled coordinator with
`semantic-gate-server --auto-approval path/to/document.json`; the same catalogue
given to `--catalog` is the classification authority.

Auto-approval is not reachable from any agent-callable surface. Pausing,
enabling and disabling rules are authenticated human control-plane operations.
