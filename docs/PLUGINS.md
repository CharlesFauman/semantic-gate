# Plugin and node-broker guide

## Components

- `ActionPlugin`: interface implemented by a reviewed integration.
- `PluginManifest`: fixed plugin ID, node ID and semantic action IDs.
- `NodeBroker`: validates execution leases and invokes one matching plugin.
- `HMACLeaseAuthority`: dependency-free development/default signer. Production deployments may substitute asymmetric signatures or workload identities.
- `SQLiteReplayStore`: consumes a lease before execution so replay cannot invoke the plugin twice.
- `RecipePlugin`: fixed executable/argument recipes for narrow local operations.

## Lease envelope

A broker accepts only a closed envelope containing:

- unique lease ID and nonce;
- request ID and request hash;
- semantic action;
- exact node and plugin audience;
- parameters and canonical parameter hash;
- policy hash;
- issue and expiry times;
- coordinator signature.

The broker verifies all fields, reruns the plugin precheck and consumes the lease before calling `execute`. Expired, replayed, tampered or misaddressed leases fail closed.

## Safe local automation

Expose a named operation such as `desktop.application.open` or `document.export_pdf`. Do not expose `shell.execute`, `osascript.run`, `powershell.run`, raw GUI coordinates, arbitrary keystrokes or caller-provided script text.

`RecipePlugin` enforces:

- an absolute reviewed executable path;
- a fixed argument vector;
- an exact parameter set;
- allowlisted values for every parameter;
- no shell interpolation;
- bounded timeout and output;
- a minimal fixed subprocess environment that does not inherit broker secrets;
- no automatic retry.

A macOS plugin can internally invoke a checked-in AppleScript file or native helper after the lease has been validated. The agent chooses only closed semantic parameters. macOS TCC remains an independent OS-level permission boundary.

A Windows plugin should use a constrained helper or JEA endpoint and run in the correct non-interactive or interactive session for the action. Never make a service-session broker silently manipulate an active user desktop.

## Audit-only host hooks

Hosts that already possess broad capabilities can migrate incrementally by
reporting content-free attempted/completed observations before removing the
old bypass. Use unique event IDs, preserve observations durably across
outages, derive the principal from its bearer capability, and report queue
loss explicitly. Observation ingestion is not approval, policy enforcement,
or evidence that an observed action passed through a non-bypassable broker.

## Remote plugins

A plugin may call a remote API, Home Assistant, another MCP server or a node-specific service. Credentials remain in that plugin's process or platform credential store. The coordinator and agent receive only redacted metadata and result fingerprints.

Remote APIs should receive the Semantic Gate request ID as their idempotency key when supported. If a timeout leaves the result unknown and no reliable postcondition can reconcile it, the request must stop in an unknown/failed state and must not retry automatically.

## Publication boundary

Reusable plugin packages should contain:

- generic schemas and semantic action names;
- dependency-injected transports and credential providers;
- simulation fixtures;
- no endpoints, account IDs, hostnames, private paths, device names or credentials.

Private deployments should contain:

- node manifests;
- endpoint and entity bindings;
- credential references;
- action allowlists and risk classifications;
- deployment scripts and service definitions.
