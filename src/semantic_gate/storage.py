#!/usr/bin/env python3
"""Durable request snapshots, controls and append-only audit metadata."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


class Ledger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS requests (
          request_id TEXT PRIMARY KEY,
          action TEXT NOT NULL,
          requester TEXT NOT NULL,
          state TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          snapshot_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
          seq INTEGER PRIMARY KEY AUTOINCREMENT,
          request_id TEXT,
          event TEXT NOT NULL,
          actor TEXT NOT NULL,
          at INTEGER NOT NULL,
          metadata_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS controls (
          key TEXT PRIMARY KEY,
          value_json TEXT NOT NULL,
          updated_at INTEGER NOT NULL,
          actor TEXT NOT NULL
        );
        """)
        self._db.commit()

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)

    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    def record_request(self, request: dict, *, event: str, actor: str, metadata: dict | None = None):
        request_id = request["request_id"]
        at = int(request.get("updated_at", request.get("created_at", 0)))
        with self._lock, self._db:
            self._db.execute(
                """INSERT INTO requests(request_id,action,requester,state,created_at,updated_at,snapshot_json)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(request_id) DO UPDATE SET state=excluded.state,
                     updated_at=excluded.updated_at,snapshot_json=excluded.snapshot_json""",
                (request_id, request["action"], request["requester"], request["state"], int(request["created_at"]), at, self._json(request)),
            )
            self._db.execute(
                "INSERT INTO audit(request_id,event,actor,at,metadata_json) VALUES(?,?,?,?,?)",
                (request_id, event, actor, at, self._json(metadata or {})),
            )

    def get_request(self, request_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT snapshot_json FROM requests WHERE request_id=?", (request_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list_requests(self, *, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 500))
        with self._lock:
            rows = self._db.execute("SELECT snapshot_json FROM requests ORDER BY updated_at DESC, request_id DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def audit_events(self, request_id: str | None = None, *, limit: int = 500) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        query = "SELECT seq,request_id,event,actor,at,metadata_json FROM audit"
        args: list[Any] = []
        if request_id is not None:
            query += " WHERE request_id=?"
            args.append(request_id)
        query += " ORDER BY seq ASC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._db.execute(query, args).fetchall()
        return [{"seq": row["seq"], "request_id": row["request_id"], "event": row["event"], "actor": row["actor"], "at": row["at"], "metadata": json.loads(row["metadata_json"])} for row in rows]

    def expire_unresolved(self, *, now: int) -> int:
        terminal = {"blocked", "cancelled", "simulated", "executed", "failed", "expired", "denied"}
        count = 0
        for request in self.list_requests(limit=500):
            if request["state"] in terminal:
                continue
            request["state"] = "expired"
            request["updated_at"] = int(now)
            self.record_request(request, event="expired_on_restart", actor="system")
            count += 1
        return count

    def set_control(self, key: str, value: Any, *, actor: str, now: int):
        if key not in {"pause_all", "paused_domains", "revoked_principals"}:
            raise ValueError("unknown control")
        with self._lock, self._db:
            self._db.execute(
                """INSERT INTO controls(key,value_json,updated_at,actor) VALUES(?,?,?,?)
                   ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,
                     updated_at=excluded.updated_at,actor=excluded.actor""",
                (key, self._json(value), int(now), actor),
            )
            self._db.execute(
                "INSERT INTO audit(request_id,event,actor,at,metadata_json) VALUES(NULL,?,?,?,?)",
                ("control_changed", actor, int(now), self._json({"key": key, "value": value})),
            )

    def controls(self) -> dict:
        result = {"pause_all": False, "paused_domains": [], "revoked_principals": []}
        with self._lock:
            rows = self._db.execute("SELECT key,value_json FROM controls").fetchall()
        for row in rows:
            result[row["key"]] = json.loads(row["value_json"])
        return result
