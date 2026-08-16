#!/usr/bin/env python3
"""Host-owned principal capabilities and browser sessions."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Mapping


class AuthError(ValueError):
    pass


@dataclass(frozen=True)
class Principal:
    principal_id: str
    role: str


class CapabilityAuthority:
    def __init__(self, master_key: bytes, principals: Mapping[str, Mapping[str, object]]):
        if len(master_key) < 32:
            raise ValueError("master key must contain at least 32 bytes")
        self._key = bytes(master_key)
        self._principals = {str(key): dict(value) for key, value in principals.items()}

    def _signature(self, purpose: str, payload: bytes) -> bytes:
        return hmac.new(self._key, purpose.encode() + b"\0" + payload, hashlib.sha256).digest()

    def token_for(self, principal_id: str) -> str:
        if principal_id not in self._principals:
            raise AuthError("unknown principal")
        digest = self._signature("capability", principal_id.encode())
        return "sg1_" + base64.urlsafe_b64encode(digest).decode().rstrip("=")

    def _principal(self, principal_id: str) -> Principal:
        config = self._principals.get(principal_id)
        if not config or config.get("enabled") is not True:
            raise AuthError("principal is unavailable")
        role = config.get("role")
        if role not in {"agent", "admin", "service"}:
            raise AuthError("principal role is invalid")
        return Principal(principal_id, str(role))

    def authenticate_bearer(self, header: str | None) -> Principal:
        if not isinstance(header, str) or not header.startswith("Bearer "):
            raise AuthError("bearer capability is required")
        supplied = header[7:].strip()
        matched = None
        for principal_id in self._principals:
            if hmac.compare_digest(supplied, self.token_for(principal_id)):
                matched = principal_id
        if matched is None:
            raise AuthError("capability is invalid")
        return self._principal(matched)

    def issue_session(self, principal_id: str, *, now: int, ttl_seconds: int) -> str:
        principal = self._principal(principal_id)
        if principal.role != "admin":
            raise AuthError("admin principal is required")
        if type(now) is not int or type(ttl_seconds) is not int or ttl_seconds < 1:
            raise AuthError("session lifetime is invalid")
        payload = json.dumps({"sub": principal_id, "exp": now + ttl_seconds}, sort_keys=True, separators=(",", ":")).encode()
        encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(self._signature("session", payload)).decode().rstrip("=")
        return encoded + "." + signature

    def verify_session(self, session: str, *, now: int) -> Principal:
        try:
            encoded, supplied = session.split(".", 1)
            payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            expected = base64.urlsafe_b64encode(self._signature("session", payload)).decode().rstrip("=")
            if not hmac.compare_digest(supplied, expected):
                raise AuthError("session signature is invalid")
            data = json.loads(payload)
        except AuthError:
            raise
        except Exception as error:
            raise AuthError("session is malformed") from error
        if type(data.get("exp")) is not int or data["exp"] <= now:
            raise AuthError("session is expired")
        return self._principal(data.get("sub"))
