#!/usr/bin/env python3
"""Generic action-plugin contract for local and remote execution brokers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PluginManifest:
    plugin_id: str
    node_id: str
    actions: tuple[str, ...]

    def __post_init__(self):
        if not self.plugin_id or not self.node_id or not self.actions:
            raise ValueError("plugin manifest fields must be non-empty")
        if any(not isinstance(action, str) or "." not in action for action in self.actions):
            raise ValueError("plugin actions must be semantic action identifiers")
        if len(set(self.actions)) != len(self.actions):
            raise ValueError("plugin actions must be unique")


class ActionPlugin:
    """Plugins expose reviewed semantic actions, never generic command execution."""

    manifest: PluginManifest

    def precheck(self, action: str, parameters: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def execute(self, action: str, parameters: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError
