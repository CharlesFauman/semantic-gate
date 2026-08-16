#!/usr/bin/env python3
"""Reviewed fixed-command plugin for local OS and GUI recipes."""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Callable, Mapping

from .plugins import ActionPlugin, PluginManifest


class RecipePluginError(ValueError):
    pass


@dataclass(frozen=True)
class Recipe:
    argv: tuple[str, ...]
    parameters: Mapping[str, tuple[str, ...]]
    timeout_seconds: int = 30

    def __post_init__(self):
        if not self.argv or not os.path.isabs(self.argv[0]):
            raise RecipePluginError("recipe executable must be an absolute path")
        placeholders={token[1:-1] for token in self.argv if token.startswith("{") and token.endswith("}")}
        if placeholders!=set(self.parameters):
            raise RecipePluginError("recipe placeholders must exactly match declared parameters")
        if type(self.timeout_seconds) is not int or not (1<=self.timeout_seconds<=300):
            raise RecipePluginError("recipe timeout is invalid")


class RecipePlugin(ActionPlugin):
    def __init__(self, *, plugin_id: str, node_id: str, recipes: Mapping[str,Recipe], runner: Callable = subprocess.run):
        if not recipes: raise RecipePluginError("at least one recipe is required")
        self.recipes=dict(recipes); self.runner=runner
        self.manifest=PluginManifest(plugin_id=plugin_id,node_id=node_id,actions=tuple(sorted(self.recipes)))

    def _argv(self, action: str, parameters: dict) -> tuple[Recipe,list[str]]:
        recipe=self.recipes.get(action)
        if recipe is None: raise RecipePluginError("action has no reviewed recipe")
        if not isinstance(parameters,dict) or set(parameters)!=set(recipe.parameters):
            raise RecipePluginError("recipe parameters do not match the reviewed schema")
        for name,allowed in recipe.parameters.items():
            if not isinstance(parameters[name],str) or parameters[name] not in allowed:
                raise RecipePluginError(f"parameter is not allowlisted: {name}")
        argv=[parameters[token[1:-1]] if token.startswith("{") and token.endswith("}") else token for token in recipe.argv]
        return recipe,argv

    def precheck(self, action: str, parameters: dict) -> dict:
        recipe,argv=self._argv(action,parameters)
        return {"eligible":os.path.isfile(argv[0]) and os.access(argv[0],os.X_OK),"executable":argv[0],"timeout_seconds":recipe.timeout_seconds}

    def execute(self, action: str, parameters: dict) -> dict:
        recipe,argv=self._argv(action,parameters)
        if not (os.path.isfile(argv[0]) and os.access(argv[0],os.X_OK)):
            raise RecipePluginError("reviewed executable is unavailable")
        completed=self.runner(argv,capture_output=True,text=True,timeout=recipe.timeout_seconds,check=False,
                              env={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8"})
        stdout=(completed.stdout or "")[:8192].strip(); stderr=(completed.stderr or "")[:8192].strip()
        if completed.returncode!=0:
            raise RecipePluginError(f"reviewed recipe failed with exit {completed.returncode}: {stderr}")
        return {"returncode":completed.returncode,"stdout":stdout}
