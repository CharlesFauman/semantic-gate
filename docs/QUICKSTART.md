# Quick start

Semantic Gate beta separates permission from execution. An agent proposes an exact action; policy and human evidence produce a signed authorization; the agent later chooses whether to submit that authorization to a fixed broker.

## Run locally

```sh
git clone https://github.com/CharlesFauman/semantic-gate.git
cd semantic-gate
python3 -m venv .venv
.venv/bin/python -m pip install .
make examples PYTHON=.venv/bin/python EXAMPLE_ENV=
```

The default examples are simulation-only. They demonstrate:

- Buzz-style verified human evidence ending at `authorized`;
- a real stdio MCP host and two downstream MCP subprocesses;
- agent-owned multi-step flow with separate unconsumed authorizations.

## Version 2 policy

```json
{
  "version": 2,
  "mode": "simulation_only",
  "execution_enabled": false,
  "authorization": {
    "audience": "example-broker",
    "ttl_seconds": 300
  },
  "workflows": {}
}
```

Approval of a valid version 2 request returns state `authorized`. It does not call the target. The public request contains metadata and authorization ID—not the bearer signature. The host-stored signed token binds request, requester, assurance, action, target, parameters, policy, approval evidence, audience and expiry.

## Safe local consumption proof

After reading the trust-boundary guide:

```sh
make example-mcp-enforcing-mock
```

This contacts only bundled local mocks. It proves direct agent target denial, explicit authorization consumption, broker recheck and one target invocation.

## Existing MCPs

Semantic Gate is not a transparent proxy. Place effectful MCP credentials behind a reviewed adapter host, remove the original effectful server from agent configuration, and prove direct denial before calling an action enforced. See [ADAPTER_HOST.md](ADAPTER_HOST.md).
