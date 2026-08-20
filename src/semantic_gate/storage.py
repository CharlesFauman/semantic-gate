#!/usr/bin/env python3
"""Durable request snapshots, controls and append-only audit metadata."""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Any


class Ledger:
    def __init__(self, path: str | Path, *, max_observations: int = 100_000, max_audit_events: int = 200_000):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.max_observations=max(1,int(max_observations)); self.max_audit_events=max(1,int(max_audit_events))
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
        CREATE TABLE IF NOT EXISTS observations (
          event_id TEXT NOT NULL,
          principal TEXT NOT NULL,
          phase TEXT NOT NULL,
          operation TEXT NOT NULL,
          semantic_class TEXT NOT NULL,
          outcome TEXT NOT NULL,
          occurred_at INTEGER NOT NULL,
          received_at INTEGER NOT NULL,
          metadata_json TEXT NOT NULL,
          observation_json TEXT NOT NULL,
          PRIMARY KEY(principal,event_id)
        );
        CREATE TABLE IF NOT EXISTS controls (
          key TEXT PRIMARY KEY,
          value_json TEXT NOT NULL,
          updated_at INTEGER NOT NULL,
          actor TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notification_outbox (
          notification_id TEXT PRIMARY KEY,
          request_id TEXT NOT NULL,
          request_hash TEXT NOT NULL,
          notify_gate_id TEXT NOT NULL,
          recipient TEXT NOT NULL,
          template_hash TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('pending','delivered','unknown')),
          attempts INTEGER NOT NULL DEFAULT 0,
          next_attempt_at INTEGER NOT NULL,
          claimed_at INTEGER,
          claim_expires_at INTEGER,
          claim_token TEXT,
          created_at INTEGER NOT NULL,
          delivered_at INTEGER,
          last_error TEXT,
          UNIQUE(request_id,request_hash,notify_gate_id,recipient,template_hash)
        );
        """)
        current_version=int(self._db.execute("PRAGMA user_version").fetchone()[0])
        if current_version == 0:
            self._db.execute("PRAGMA user_version=1")
        self._db.commit()

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)

    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    def schema_version(self) -> int:
        with self._lock:
            return int(self._db.execute("PRAGMA user_version").fetchone()[0])

    @staticmethod
    def _notification(row: sqlite3.Row | None) -> dict | None:
        return dict(row) if row is not None else None

    def get_notification(self, notification_id: str) -> dict | None:
        with self._lock:
            row=self._db.execute("SELECT * FROM notification_outbox WHERE notification_id=?",(notification_id,)).fetchone()
        return self._notification(row)

    def notifications_for_request(self, request_id: str) -> list[dict]:
        if not isinstance(request_id,str) or not request_id:
            raise ValueError("request_id must be a non-empty string")
        with self._lock:
            rows=self._db.execute(
                "SELECT * FROM notification_outbox WHERE request_id=? ORDER BY created_at,notification_id",
                (request_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def notification_health(self) -> dict:
        with self._lock:
            rows=self._db.execute("SELECT state,COUNT(*) AS count,MIN(created_at) AS oldest FROM notification_outbox GROUP BY state").fetchall()
        result={"pending":0,"delivered":0,"unknown":0,"oldest_pending_at":None}
        for row in rows:
            state=str(row["state"])
            if state in result:
                result[state]=int(row["count"])
            if state=="pending":
                result["oldest_pending_at"]=row["oldest"]
        return result

    def enqueue_notification(self, *, request_id: str, request_hash: str, notify_gate_id: str, recipient: str, template_hash: str, now: int) -> dict:
        binding=(request_id,request_hash,notify_gate_id,recipient,template_hash)
        if any(not isinstance(value,str) or not value for value in binding):
            raise ValueError("notification binding fields must be non-empty strings")
        digest=hashlib.sha256(self._json(binding).encode()).hexdigest()
        notification_id="notice_"+digest
        with self._lock,self._db:
            self._db.execute(
                """INSERT OR IGNORE INTO notification_outbox(
                   notification_id,request_id,request_hash,notify_gate_id,recipient,template_hash,state,attempts,next_attempt_at,created_at
                   ) VALUES(?,?,?,?,?,?,'pending',0,?,?)""",
                (notification_id,*binding,int(now),int(now)),
            )
            row=self._db.execute("SELECT * FROM notification_outbox WHERE notification_id=?",(notification_id,)).fetchone()
        return dict(row)

    def claim_notification(self, *, now: int, lease_seconds: int) -> dict | None:
        if type(lease_seconds) is not int or lease_seconds < 1:
            raise ValueError("lease_seconds must be positive")
        now=int(now); token=secrets.token_hex(16)
        with self._lock,self._db:
            row=self._db.execute(
                """SELECT notification_id FROM notification_outbox
                   WHERE state='pending' AND next_attempt_at<=?
                     AND (claim_token IS NULL OR claim_expires_at<=?)
                   ORDER BY next_attempt_at,created_at,notification_id LIMIT 1""",
                (now,now),
            ).fetchone()
            if row is None:
                return None
            changed=self._db.execute(
                """UPDATE notification_outbox SET claim_token=?,claimed_at=?,claim_expires_at=?,attempts=attempts+1
                   WHERE notification_id=? AND state='pending'
                     AND (claim_token IS NULL OR claim_expires_at<=?)""",
                (token,now,now+lease_seconds,row["notification_id"],now),
            )
            if changed.rowcount != 1:
                return None
            claimed=self._db.execute("SELECT * FROM notification_outbox WHERE notification_id=?",(row["notification_id"],)).fetchone()
        return dict(claimed)

    def _claimed_notification(self, notification_id: str, claim_token: str, *, at: int) -> sqlite3.Row:
        row=self._db.execute("SELECT * FROM notification_outbox WHERE notification_id=?",(notification_id,)).fetchone()
        if row is None or row["state"] != "pending" or not isinstance(claim_token,str) or row["claim_token"] != claim_token or row["claim_expires_at"] < int(at):
            raise ValueError("notification claim is missing, stale, or already completed")
        return row

    def complete_notification(self, notification_id: str, *, claim_token: str, delivered_at: int) -> dict:
        with self._lock,self._db:
            self._claimed_notification(notification_id,claim_token,at=delivered_at)
            self._db.execute(
                """UPDATE notification_outbox SET state='delivered',delivered_at=?,claim_token=NULL,
                   claimed_at=NULL,claim_expires_at=NULL,last_error=NULL WHERE notification_id=?""",
                (int(delivered_at),notification_id),
            )
            row=self._db.execute("SELECT * FROM notification_outbox WHERE notification_id=?",(notification_id,)).fetchone()
        return dict(row)

    def release_notification(self, notification_id: str, *, claim_token: str, now: int, backoff_seconds: int, last_error: str | None = None, delivery_unknown: bool = False) -> dict:
        if type(backoff_seconds) is not int or backoff_seconds < 0:
            raise ValueError("backoff_seconds must be non-negative")
        if last_error is not None and (not isinstance(last_error,str) or len(last_error)>500):
            raise ValueError("last_error must be a bounded string")
        with self._lock,self._db:
            self._claimed_notification(notification_id,claim_token,at=now)
            state="unknown" if delivery_unknown else "pending"
            self._db.execute(
                """UPDATE notification_outbox SET state=?,next_attempt_at=?,claim_token=NULL,
                   claimed_at=NULL,claim_expires_at=NULL,last_error=? WHERE notification_id=?""",
                (state,int(now)+backoff_seconds,last_error,notification_id),
            )
            row=self._db.execute("SELECT * FROM notification_outbox WHERE notification_id=?",(notification_id,)).fetchone()
        return dict(row)

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
            self._prune_audit_locked()

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

    def _prune_audit_locked(self):
        self._db.execute("DELETE FROM audit WHERE seq NOT IN (SELECT seq FROM audit ORDER BY seq DESC LIMIT ?)",(self.max_audit_events,))

    def record_audit(self, *, event: str, actor: str, at: int, metadata: dict, request_id: str | None = None):
        with self._lock,self._db:
            self._db.execute(
                "INSERT INTO audit(request_id,event,actor,at,metadata_json) VALUES(?,?,?,?,?)",
                (request_id,event,actor,int(at),self._json(metadata)),
            )
            self._prune_audit_locked()

    def get_observation(self, event_id: str, *, principal: str) -> dict | None:
        with self._lock:
            row=self._db.execute("SELECT observation_json FROM observations WHERE principal=? AND event_id=?",(principal,event_id)).fetchone()
        return json.loads(row[0]) if row else None

    @staticmethod
    def _observation_payload(observation: dict) -> dict:
        return {key:value for key,value in observation.items() if key!="received_at"}

    def recent_observations(self, *, limit: int = 100) -> list[dict]:
        limit=max(1,min(int(limit),1000))
        with self._lock:
            rows=self._db.execute("SELECT observation_json FROM observations ORDER BY received_at DESC,rowid DESC LIMIT ?",(limit,)).fetchall()
        return [json.loads(row[0]) for row in reversed(rows)]

    def record_observation(self, observation: dict) -> dict:
        encoded=self._json(observation); comparable=self._observation_payload(observation)
        with self._lock,self._db:
            row=self._db.execute("SELECT observation_json FROM observations WHERE principal=? AND event_id=?",(observation["principal"],observation["event_id"])).fetchone()
            if row:
                existing=json.loads(row[0])
                if self._observation_payload(existing)!=comparable: raise ValueError("conflicting observation event_id")
                return existing
            inserted=self._db.execute(
                """INSERT OR IGNORE INTO observations(event_id,principal,phase,operation,semantic_class,outcome,occurred_at,received_at,metadata_json,observation_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (observation["event_id"],observation["principal"],observation["phase"],observation["operation"],observation["semantic_class"],observation["outcome"],int(observation["occurred_at"]),int(observation["received_at"]),self._json(observation["metadata"]),encoded),
            )
            if inserted.rowcount==0:
                existing=json.loads(self._db.execute("SELECT observation_json FROM observations WHERE principal=? AND event_id=?",(observation["principal"],observation["event_id"])).fetchone()[0])
                if self._observation_payload(existing)!=comparable: raise ValueError("conflicting observation event_id")
                return existing
            self._db.execute(
                "INSERT INTO audit(request_id,event,actor,at,metadata_json) VALUES(NULL,?,?,?,?)",
                ("permission_observed",observation["principal"],int(observation["received_at"]),self._json({key:observation[key] for key in ("event_id","phase","operation","semantic_class","outcome","occurred_at","metadata")})),
            )
            self._db.execute("DELETE FROM observations WHERE rowid NOT IN (SELECT rowid FROM observations ORDER BY received_at DESC,rowid DESC LIMIT ?)",(self.max_observations,))
            self._prune_audit_locked()
        return dict(observation)

    def expire_unresolved(self, *, now: int) -> int:
        terminal = {"blocked", "cancelled", "simulated", "executed", "failed", "expired", "denied"}
        with self._lock:
            rows=self._db.execute("SELECT snapshot_json FROM requests ORDER BY updated_at DESC").fetchall()
        count = 0
        for row in rows:
            request=json.loads(row["snapshot_json"])
            if request["state"] in terminal:
                continue
            request["state"] = "expired"
            request["updated_at"] = int(now)
            self.record_request(request, event="expired_on_restart", actor="system")
            count += 1
        return count

    def set_control(self, key: str, value: Any, *, actor: str, now: int):
        if key not in {"pause_all", "paused_domains", "revoked_principals", "auto_approval_paused", "disabled_auto_rules"}:
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
            self._prune_audit_locked()

    def controls(self) -> dict:
        result = {"pause_all": False, "paused_domains": [], "revoked_principals": [],
                  "auto_approval_paused": False, "disabled_auto_rules": []}
        with self._lock:
            rows = self._db.execute("SELECT key,value_json FROM controls").fetchall()
        for row in rows:
            result[row["key"]] = json.loads(row["value_json"])
        return result
