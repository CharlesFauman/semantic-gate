# Auto-approval examples

`global-simulation.json` is a generic, simulation-only auto-approval document.

- The standing `global_simulation_rule` auto-approves the approval gate for every
  catalogued action above the prohibited safety floor. It only applies while
  execution is disabled, and it never authorizes execution: `execution_enabled`
  remains a separate hard stop.
- The floor must be declared in full. A document cannot shrink it, so
  credentials, spending, external human communication, destructive or
  irreversible git, undeclared infrastructure effects and arbitrary
  terminal/shell/command actions always keep the ordinary human gate.
- `rules` holds scoped rules for the later execution-enabled promotion path. Each
  binds one canonical repository, exact refs, declared deploy target/environment,
  host-authenticated requesters/nodes, closed parameter constraints and a review
  date. Wildcards, near-match repository strings and path traversal fail to load.
- Placeholders only. Replace the requester, node and repository with your own
  host-authenticated identities in your private repository, and keep the review
  and expiry dates short enough that a human revisits them.

Auto-approval is not reachable from any agent-callable surface. Pausing,
enabling and disabling rules are authenticated human control-plane operations.
