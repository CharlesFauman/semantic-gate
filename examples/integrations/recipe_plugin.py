#!/usr/bin/env python3
"""Fixed recipe plugin example; no caller-supplied command text."""
from semantic_gate.recipe_plugin import Recipe,RecipePlugin

plugin=RecipePlugin(
    plugin_id="example-document-plugin",
    node_id="example-node",
    recipes={
        "document.export_pdf":Recipe(
            argv=("/usr/bin/true","{quality}"),
            parameters={"quality":("screen","print")},
            timeout_seconds=10,
        )
    },
)
print(plugin.precheck("document.export_pdf",{"quality":"screen"}))
