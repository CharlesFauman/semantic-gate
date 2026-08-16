#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from semantic_gate.broker import BrokerError, HMACLeaseAuthority, NodeBroker, SQLiteReplayStore
from semantic_gate.plugins import ActionPlugin, PluginManifest


class RecordingPlugin(ActionPlugin):
    manifest = PluginManifest(plugin_id="example.device", node_id="node-a", actions=("device.power_off",))

    def __init__(self):
        self.calls = []

    def precheck(self, action, parameters):
        return {"eligible": parameters.get("target") == "example"}

    def execute(self, action, parameters):
        self.calls.append((action, parameters))
        return {"ok": True}


class NodeBrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.authority = HMACLeaseAuthority(bytes.fromhex("44" * 32))
        self.plugin = RecordingPlugin()
        self.broker = NodeBroker(
            node_id="node-a", plugins=[self.plugin], lease_authority=self.authority,
            replay_store=SQLiteReplayStore(Path(self.tmp.name) / "replay.sqlite3"),
            clock=lambda: 100,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def lease(self, **changes):
        fields = {
            "lease_id":"lease-1","request_id":"req-1","request_hash":"hash-1",
            "action":"device.power_off","node_id":"node-a","plugin_id":"example.device",
            "parameters":{"target":"example"},"policy_hash":"policy-1",
            "issued_at":90,"expires_at":110,"nonce":"nonce-1",
        }
        fields.update(changes)
        return self.authority.issue(fields)

    def test_exact_lease_executes_once_and_is_auditable(self):
        result = self.broker.execute(self.lease())
        self.assertEqual({"ok":True}, result["result"])
        self.assertEqual(1, len(self.plugin.calls))
        with self.assertRaisesRegex(BrokerError, "already consumed"):
            self.broker.execute(self.lease())
        self.assertEqual(1, len(self.plugin.calls))

    def test_wrong_node_plugin_action_parameters_expiry_and_signature_fail_closed(self):
        variants = [
            self.lease(node_id="node-b", lease_id="l2"),
            self.lease(plugin_id="other", lease_id="l3"),
            self.lease(action="system.shell.execute", lease_id="l4"),
            self.lease(parameters={"target":"changed"}, lease_id="l5"),
            self.lease(expires_at=100, lease_id="l6"),
        ]
        tampered = self.lease(lease_id="l7"); tampered["request_hash"] = "changed"
        variants.append(tampered)
        for lease in variants:
            with self.subTest(lease=lease), self.assertRaises(BrokerError):
                self.broker.execute(lease)
        self.assertEqual([], self.plugin.calls)

    def test_precheck_is_read_only_and_does_not_consume_lease(self):
        lease = self.lease(lease_id="precheck")
        self.assertTrue(self.broker.precheck(lease)["eligible"])
        self.assertEqual([], self.plugin.calls)
        self.broker.execute(lease)
        self.assertEqual(1, len(self.plugin.calls))


if __name__ == "__main__":
    unittest.main()
