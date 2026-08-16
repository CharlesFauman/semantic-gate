#!/usr/bin/env python3
"""Host-only credential values with redacted public metadata."""
from __future__ import annotations

import json
from pathlib import Path


class CredentialRegistry:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        raw = json.loads(self.path.read_text()) if self.path.exists() else {"credentials": {}}
        credentials = raw.get("credentials")
        if not isinstance(credentials, dict):
            raise ValueError("credential registry must contain an object")
        self._credentials = credentials

    def public_inventory(self) -> list[dict]:
        result = []
        for credential_id, item in self._credentials.items():
            if not isinstance(item, dict):
                continue
            disabled = item.get("disabled") is True
            configured = isinstance(item.get("value"), str) and bool(item["value"])
            result.append({
                "credential_id": credential_id,
                "adapter": item.get("adapter", "unknown"),
                "kind": item.get("kind", "unknown"),
                "status": "disabled" if disabled else "available" if configured else "missing",
            })
        return result

    def require(self, credential_id: str) -> str:
        item = self._credentials.get(credential_id)
        if not isinstance(item, dict) or item.get("disabled") is True:
            raise KeyError(credential_id)
        value = item.get("value")
        if not isinstance(value, str) or not value:
            raise KeyError(credential_id)
        return value
