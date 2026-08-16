"""Deterministic semantic permission gates for agent tools."""

__version__ = "0.3.0b1"

from .authorization import (
    AuthorizationBroker,
    AuthorizationError,
    Ed25519AuthorizationAuthority,
    Ed25519AuthorizationVerifier,
    HMACAuthorizationAuthority,
    SQLiteAuthorizationStore,
)
from .approvals import ApprovalTransportError, Ed25519ApprovalRoster, SignedApprovalBridge, sign_approval
from .adapter_host import AdapterConfigError, DeclarativeAdapterHost, load_adapter_config

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
from .broker import HMACLeaseAuthority, NodeBroker, SQLiteReplayStore
from .client import SemanticGateClient
from .plugins import ActionPlugin, PluginManifest
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
    "CapabilityAuthority",
    "HMACLeaseAuthority",
    "NodeBroker",
    "PluginManifest",
    "Principal",
    "Recipe",
    "RecipePlugin",
    "AuthorizationBroker",
    "AuthorizationError",
    "Ed25519AuthorizationAuthority",
    "Ed25519AuthorizationVerifier",
    "HMACAuthorizationAuthority",
    "SQLiteAuthorizationStore",
    "ApprovalTransportError",
    "Ed25519ApprovalRoster",
    "SignedApprovalBridge",
    "sign_approval",
    "AdapterConfigError",
    "DeclarativeAdapterHost",
    "load_adapter_config",
    "SQLiteReplayStore",
    "SemanticGateClient",
]
