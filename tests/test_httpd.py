#!/usr/bin/env python3
from __future__ import annotations

import json
import threading
import unittest
from urllib.request import urlopen

from semantic_gate.httpd import make_http_server
from tests.test_server import SemanticGateApplicationTests


class HTTPServerTests(SemanticGateApplicationTests):
    def test_real_http_health_and_size_limit(self):
        server=make_http_server(self.app,"127.0.0.1",0)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            with urlopen(f"http://127.0.0.1:{server.server_port}/health",timeout=2) as response:
                self.assertEqual("ok",json.load(response)["status"])
        finally:
            server.shutdown(); server.server_close(); thread.join(2)


if __name__=="__main__": unittest.main()
