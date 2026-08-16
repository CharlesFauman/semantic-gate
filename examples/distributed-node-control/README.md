# Distributed node control example

This simulation-only example shows how one semantic action can target a capability owned by another machine without exposing a shell or GUI automation primitive.

The coordinator policy authorizes `desktop.application.open`. After every gate passes, a production coordinator would issue a signed, expiring, single-use lease addressed to `example-workstation` and plugin `example.reviewed-apps`.

The node plugin exposes one reviewed recipe:

```python
from semantic_gate import Recipe, RecipePlugin

plugin = RecipePlugin(
    plugin_id="example.reviewed-apps",
    node_id="example-workstation",
    recipes={
        "desktop.application.open": Recipe(
            argv=("/opt/example/bin/open-reviewed-app", "{application}"),
            parameters={"application": ("example-editor", "example-viewer")},
        )
    },
)
```

The caller can choose only an allowlisted application. It cannot submit command text, a script, a path, GUI coordinates or keystrokes. The executable path and argument vector belong to reviewed host configuration.

`lease.json` is an illustrative unsigned payload. Real leases are produced by a trusted coordinator and carry a signature plus canonical parameter hash. Do not accept an unsigned JSON document as execution authority.
