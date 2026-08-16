#!/usr/bin/env python3
from __future__ import annotations

import threading
import unittest

from semantic_gate.client import SemanticGateClient
from semantic_gate.httpd import make_http_server
from tests.test_server import SemanticGateApplicationTests


class ClientTests(SemanticGateApplicationTests):
    def test_default_sdk_request_omits_floor_for_old_server_compatibility(self):
        client=SemanticGateClient("example-scheme:gateway","token")
        captured=[]
        client._call=lambda method,path,payload=None: captured.append(payload) or {}
        client.request_action("device.power_off",parameters={},context={},idempotency_key="old-server")
        self.assertNotIn("minimum_control",captured[0])

    def test_direct_sdk_uses_same_identity_and_request_contract(self):
        server=make_http_server(self.app,"127.0.0.1",0)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            client=SemanticGateClient(f"http://127.0.0.1:{server.server_port}",self.authority.token_for("agent"))
            self.assertEqual("device.power_off",client.list_actions()[0]["action"])
            request=client.request_action("device.power_off",parameters={},context={"surface":"sdk"},idempotency_key="sdk-one",minimum_control="step_up")
            self.assertEqual("agent",request["requester"])
            self.assertEqual("waiting_for_approval",request["state"])
            self.assertEqual("step_up",request["minimum_control"])
            self.assertEqual("step_up",request["effective_control"])
            observation=client.observe_permission(event_id="sdk-tool:completed",phase="completed",operation="terminal",semantic_class="compute.exec.arbitrary",outcome="succeeded",occurred_at=99,metadata={"surface":"sdk"})
            self.assertEqual("agent",observation["principal"])
            self.assertEqual("cancelled",client.cancel_request(request["request_id"])["state"])
        finally:
            server.shutdown(); server.server_close(); thread.join(2)


if __name__=="__main__": unittest.main()
