#!/usr/bin/env python3
"""Launch the example gate host exactly as an MCP client would."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from stdio_mcp_client import StdioMCPClient


def main() -> None:
    host=Path(__file__).with_name("existing_mcp_adapter.py")
    client=StdioMCPClient([sys.executable,str(host),"--serve"])
    try:
        actions=client.call_tool("list_actions",{})
        request=client.call_tool("request_action",{
            "action":"order.place","parameters":{"sku":"example-sku"},
            "context":{"surface":"smoke-client"},"idempotency_key":"mcp-host-smoke-1",
        })
        assert any(item["action"]=="order.place" for item in actions)
        assert request["state"]=="waiting_for_approval"
        print(json.dumps({"ok":True,"execution_enabled":False,"agent_connected_to_semantic_gate":True,"available_actions":len(actions),"request_state":request["state"]},sort_keys=True))
    finally:
        client.close()


if __name__=="__main__": main()
