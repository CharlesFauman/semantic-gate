#!/usr/bin/env python3
"""Strict declarative host for fixed downstream MCP reads and authorization targets."""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any,Callable,Mapping

from .downstream_mcp import StdioMCPClient
from .authorization import UnknownOutcomeError


class AdapterConfigError(ValueError):
    pass


NAME=re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
TOOL=re.compile(r"^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+$")
ENV=re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
TOP={"version","broker_id","downstreams","reads","actions"}
DOWNSTREAM={"command","pass_environment","timeout_seconds"}
READ={"server","tool"}
ACTION_REQUIRED={"target","server","tool","recheck_read","outcome"}
ACTION_ALLOWED=ACTION_REQUIRED|{"idempotency_field"}


def _copy(value: Any):
    try: return json.loads(json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False))
    except (TypeError,ValueError,OverflowError,RecursionError) as error: raise AdapterConfigError("adapter config must be strict JSON") from error


def _exact(value: Mapping[str,Any],fields: set[str],label: str):
    unknown=set(value)-fields; missing=fields-set(value)
    if unknown or missing: raise AdapterConfigError(f"{label} fields are invalid")


def load_adapter_config(source: str|Path|Mapping[str,Any]) -> dict:
    try: raw=json.loads(Path(source).read_text()) if isinstance(source,(str,Path)) else source
    except Exception as error: raise AdapterConfigError("adapter config file is invalid") from error
    if not isinstance(raw,Mapping): raise AdapterConfigError("adapter config must be an object")
    raw=_copy(raw); _exact(raw,TOP,"adapter config")
    if raw["version"]!=1 or not isinstance(raw["broker_id"],str) or not NAME.fullmatch(raw["broker_id"]): raise AdapterConfigError("adapter version or broker_id is invalid")
    downstreams=raw["downstreams"]
    if not isinstance(downstreams,dict) or not downstreams: raise AdapterConfigError("downstreams must be a non-empty object")
    for server,spec in downstreams.items():
        if not isinstance(server,str) or not NAME.fullmatch(server) or not isinstance(spec,dict): raise AdapterConfigError("downstream name or spec is invalid")
        _exact(spec,DOWNSTREAM,f"downstream {server}")
        command=spec["command"]
        if not isinstance(command,list) or not 1<=len(command)<=32 or any(not isinstance(item,str) or not item or len(item)>4096 or "\x00" in item for item in command): raise AdapterConfigError("downstream command must be a bounded string list")
        if not Path(command[0]).is_absolute(): raise AdapterConfigError("downstream executable must be absolute")
        passed=spec["pass_environment"]
        if not isinstance(passed,list) or len(passed)!=len(set(passed)) or any(not isinstance(item,str) or not ENV.fullmatch(item) for item in passed): raise AdapterConfigError("pass_environment must contain unique environment names")
        timeout=spec["timeout_seconds"]
        if type(timeout) is not int or not 1<=timeout<=300: raise AdapterConfigError("timeout_seconds must be between 1 and 300")
    reads=raw["reads"]
    if not isinstance(reads,dict): raise AdapterConfigError("reads must be an object")
    for name,spec in reads.items():
        if not isinstance(name,str) or not TOOL.fullmatch(name) or not isinstance(spec,dict): raise AdapterConfigError("read mapping is invalid")
        _exact(spec,READ,f"read {name}")
        if spec["server"] not in downstreams or not isinstance(spec["tool"],str) or not TOOL.fullmatch(spec["tool"]): raise AdapterConfigError("read server or tool is invalid")
    actions=raw["actions"]
    if not isinstance(actions,dict) or not actions: raise AdapterConfigError("actions must be a non-empty object")
    targets=set()
    for action,spec in actions.items():
        if not isinstance(action,str) or not TOOL.fullmatch(action) or not isinstance(spec,dict): raise AdapterConfigError("action mapping is invalid")
        if set(spec)-ACTION_ALLOWED or ACTION_REQUIRED-set(spec): raise AdapterConfigError(f"action {action} fields are invalid")
        if spec["server"] not in downstreams or spec["recheck_read"] not in reads: raise AdapterConfigError("action server or recheck mapping is invalid")
        if not isinstance(spec["target"],str) or not TOOL.fullmatch(spec["target"]) or not isinstance(spec["tool"],str) or not TOOL.fullmatch(spec["tool"]): raise AdapterConfigError("action target or tool is invalid")
        if spec["outcome"] not in {"idempotent","reconcilable"}: raise AdapterConfigError("action outcome must be idempotent or reconcilable")
        if spec["outcome"]=="idempotent" and (not isinstance(spec.get("idempotency_field"),str) or not NAME.fullmatch(spec["idempotency_field"])): raise AdapterConfigError("idempotent action requires idempotency_field")
        if spec["outcome"]=="reconcilable" and "idempotency_field" in spec: raise AdapterConfigError("reconcilable action cannot declare idempotency_field")
        if spec["target"] in targets: raise AdapterConfigError("target is mapped by multiple actions")
        targets.add(spec["target"])
    return raw


class DeclarativeAdapterHost:
    """Owns fixed downstream clients; exposes reads and broker action callables only."""
    def __init__(self,config: str|Path|Mapping[str,Any],*,environment: Mapping[str,str]|None=None,client_factory: Callable[...,Any]=StdioMCPClient):
        self.config=load_adapter_config(config); self.environment=dict(os.environ if environment is None else environment); self.client_factory=client_factory; self.clients={}; self.started=False

    def start(self):
        if self.started: return self
        try:
            for server,spec in self.config["downstreams"].items():
                missing=[name for name in spec["pass_environment"] if name not in self.environment]
                if missing: raise AdapterConfigError(f"downstream {server} environment is missing: {missing}")
                env={name:self.environment[name] for name in spec["pass_environment"]}
                self.clients[server]=self.client_factory(spec["command"],environment=env,timeout_seconds=spec["timeout_seconds"])
        except Exception:
            self.close(); raise
        self.started=True; return self

    def close(self):
        first=None
        for client in reversed(list(self.clients.values())):
            try: client.close()
            except Exception as error:
                if first is None: first=error
        self.clients={}; self.started=False
        if first is not None: raise AdapterConfigError(f"downstream close failed: {type(first).__name__}") from first

    def _client(self,server: str):
        if not self.started: raise AdapterConfigError("adapter host is not started")
        return self.clients[server]

    def call_read(self,name: str,arguments: Mapping[str,Any]) -> dict:
        spec=self.config["reads"].get(name)
        if spec is None: raise AdapterConfigError("read mapping is unavailable")
        result=self._client(spec["server"]).call_tool(spec["tool"],_copy(arguments))
        if not isinstance(result,dict): raise AdapterConfigError("downstream read result must be an object")
        return _copy(result)

    def register_reads(self,registry: Any) -> Any:
        for name in self.config["reads"]:
            registry.register_read(name,lambda arguments,read_name=name:self.call_read(read_name,arguments))
        return registry

    def broker_actions(self) -> dict:
        result={}
        for action,spec in self.config["actions"].items():
            def recheck(arguments,read_name=spec["recheck_read"]): return self.call_read(read_name,arguments)
            def execute(arguments,server=spec["server"],tool=spec["tool"],idempotency_field=spec.get("idempotency_field")):
                if idempotency_field is not None and idempotency_field not in arguments: raise AdapterConfigError("idempotency field is missing from authorized parameters")
                try: value=self._client(server).call_tool(tool,_copy(arguments))
                except Exception as error: raise UnknownOutcomeError("downstream effect outcome requires reconciliation") from error
                if not isinstance(value,dict): raise AdapterConfigError("downstream target result must be an object")
                return _copy(value)
            result[action]={"target":spec["target"],"outcome":spec["outcome"],"recheck":recheck,"execute":execute}
        return result


def main(argv: list[str]|None=None) -> int:
    parser=argparse.ArgumentParser(description="Validate a closed Semantic Gate downstream MCP adapter config")
    parser.add_argument("--config",required=True)
    args=parser.parse_args(argv)
    try: config=load_adapter_config(args.config)
    except AdapterConfigError as error: parser.error(str(error))
    print(json.dumps({"ok":True,"broker_id":config["broker_id"],"downstreams":len(config["downstreams"]),"reads":len(config["reads"]),"actions":len(config["actions"])},sort_keys=True))
    return 0


if __name__=="__main__": raise SystemExit(main())
