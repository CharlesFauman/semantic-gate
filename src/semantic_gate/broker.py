#!/usr/bin/env python3
"""Distributed node broker with signed, expiring, single-use execution leases."""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from .plugins import ActionPlugin


class BrokerError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError) as error:
        raise BrokerError("lease must contain strict JSON values") from error


class HMACLeaseAuthority:
    """Default signer; deployments may replace this with SPIFFE or asymmetric identities."""

    def __init__(self, key: bytes):
        if len(key) < 32:
            raise ValueError("lease key must contain at least 32 bytes")
        self.key = bytes(key)

    def issue(self, fields: dict) -> dict:
        lease = json.loads(_canonical(fields))
        lease["parameters_hash"] = hashlib.sha256(_canonical(lease.get("parameters"))).hexdigest()
        lease["signature"] = hmac.new(self.key, _canonical(lease), hashlib.sha256).hexdigest()
        return lease

    def verify(self, lease: dict) -> bool:
        supplied = lease.get("signature")
        if not isinstance(supplied, str):
            return False
        body = {key: value for key, value in lease.items() if key != "signature"}
        expected = hmac.new(self.key, _canonical(body), hashlib.sha256).hexdigest()
        return hmac.compare_digest(supplied, expected)


class SQLiteReplayStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS consumed(lease_id TEXT PRIMARY KEY, consumed_at INTEGER NOT NULL)")
        self.db.commit()

    def consume(self, lease_id: str, now: int):
        try:
            with self.lock, self.db:
                self.db.execute("INSERT INTO consumed(lease_id,consumed_at) VALUES(?,?)", (lease_id, int(now)))
        except sqlite3.IntegrityError as error:
            raise BrokerError("lease was already consumed") from error


class NodeBroker:
    REQUIRED = {
        "lease_id", "request_id", "request_hash", "action", "node_id", "plugin_id",
        "parameters", "parameters_hash", "policy_hash", "issued_at", "expires_at", "nonce", "signature",
    }

    def __init__(self, *, node_id: str, plugins: Iterable[ActionPlugin], lease_authority: HMACLeaseAuthority, replay_store: SQLiteReplayStore, clock):
        self.node_id = node_id
        self.authority = lease_authority
        self.replay = replay_store
        self.clock = clock
        self.plugins: dict[str, ActionPlugin] = {}
        self.actions: dict[str, ActionPlugin] = {}
        for plugin in plugins:
            manifest = plugin.manifest
            if manifest.node_id != node_id or manifest.plugin_id in self.plugins:
                raise BrokerError("plugin manifest does not belong to this broker or is duplicated")
            self.plugins[manifest.plugin_id] = plugin
            for action in manifest.actions:
                if action in self.actions:
                    raise BrokerError("semantic action is registered by multiple plugins")
                self.actions[action] = plugin

    def _validate(self, lease: dict) -> tuple[ActionPlugin, dict]:
        if not isinstance(lease, dict) or set(lease) != self.REQUIRED:
            raise BrokerError("lease envelope is malformed")
        if not self.authority.verify(lease):
            raise BrokerError("lease signature is invalid")
        if lease["node_id"] != self.node_id:
            raise BrokerError("lease is addressed to a different node")
        if type(lease["issued_at"]) is not int or type(lease["expires_at"]) is not int or not (lease["issued_at"] <= self.clock() < lease["expires_at"]):
            raise BrokerError("lease is not currently valid")
        plugin = self.plugins.get(lease["plugin_id"])
        if plugin is None or lease["action"] not in plugin.manifest.actions:
            raise BrokerError("lease plugin or action is unavailable")
        parameters = lease["parameters"]
        if not isinstance(parameters, dict):
            raise BrokerError("lease parameters must be an object")
        if hashlib.sha256(_canonical(parameters)).hexdigest() != lease["parameters_hash"]:
            raise BrokerError("lease parameters do not match their hash")
        return plugin, parameters

    def precheck(self, lease: dict) -> dict:
        plugin, parameters = self._validate(lease)
        result = plugin.precheck(lease["action"], parameters)
        if not isinstance(result, dict) or result.get("eligible") is not True:
            raise BrokerError("plugin precheck did not authorize execution")
        return result

    def execute(self, lease: dict) -> dict:
        plugin, parameters = self._validate(lease)
        precheck = plugin.precheck(lease["action"], parameters)
        if not isinstance(precheck, dict) or precheck.get("eligible") is not True:
            raise BrokerError("plugin precheck did not authorize execution")
        self.replay.consume(lease["lease_id"], self.clock())
        result = plugin.execute(lease["action"], parameters)
        if not isinstance(result, dict):
            raise BrokerError("plugin result must be an object")
        return {"lease_id": lease["lease_id"], "request_id": lease["request_id"], "result": result}
