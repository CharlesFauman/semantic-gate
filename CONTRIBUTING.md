# Contributing

## Principles

- Keep the core independent of any agent framework, vendor, account or private environment.
- Add behavior with tests first.
- Default examples to simulation-only.
- Never add credentials, live endpoints or personal identifiers.
- Treat policy widening and new gate kinds as security-sensitive changes.
- Keep approval and execution absent from the agent-callable MCP surface.

## Development

```sh
python -m pip install --no-deps -e .
python -m unittest discover -s tests -v
```

## Adding a generic example

1. Use placeholder actors, targets and provider names.
2. Include no live URL, credential field or absolute machine path.
3. Keep `mode` as `simulation_only` and `execution_enabled` as `false`.
4. Include notification, approval and pre-execution recheck gates.
5. Add tests for failed preconditions, forged approval and idempotency.

Private consumers should implement their actual integrations in their own
repositories. Contribute only a generalized mock workflow here.
