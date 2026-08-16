#!/usr/bin/env python3
from __future__ import annotations

import threading
import unittest

from semantic_gate.client import SemanticGateClient
from semantic_gate.httpd import make_http_server
from tests.test_server import SemanticGateApplicationTests


class ClientTests(SemanticGateApplicationTests):
    def test_direct_sdk_uses_same_identity_and_request_contract(self):
        server=make_http_server(self.app,"127.0.0.1",0)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            client=SemanticGateClient(f"http://127.0.0.1:{server.server_port}",self.authority.token_for("agent"))
            self.assertEqual("device.power_off",client.list_actions()[0]["action"])
            request=client.request_action("device.power_off",parameters={},context={"surface":"sdk"},idempotency_key="sdk-one")
            self.assertEqual("agent",request["requester"])
            self.assertEqual("waiting_for_approval",request["state"])
            self.assertEqual("cancelled",client.cancel_request(request["request_id"])["state"])
        finally:
            server.shutdown(); server.server_close(); thread.join(2)


if __name__=="__main__": unittest.main()
