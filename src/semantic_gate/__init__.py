"""Deterministic semantic permission gates for agent tools."""

from .engine import (
    ApprovalRejected,
    ExecutionAuthority,
    GatePolicyError,
    GatewayEngine,
    RecordingNotifier,
    ToolRegistry,
    load_policy,
)
from .auth import CapabilityAuthority, Principal
from .autoapproval import AutoApprovalPolicy, AutoApprovalPolicyError
from .broker import HMACLeaseAuthority, NodeBroker, SQLiteReplayStore
from .client import SemanticGateClient
from .plugins import ActionPlugin, PluginManifest
from .projection import build_decision_card, render_decision_card_text
from .recipe_plugin import Recipe, RecipePlugin

__all__ = [
    "ApprovalRejected",
    "ExecutionAuthority",
    "GatePolicyError",
    "GatewayEngine",
    "RecordingNotifier",
    "ToolRegistry",
    "load_policy",
    "ActionPlugin",
    "AutoApprovalPolicy",
    "AutoApprovalPolicyError",
    "CapabilityAuthority",
    "HMACLeaseAuthority",
    "NodeBroker",
    "PluginManifest",
    "Principal",
    "Recipe",
    "RecipePlugin",
    "SQLiteReplayStore",
    "SemanticGateClient",
    "build_decision_card",
    "render_decision_card_text",
]
