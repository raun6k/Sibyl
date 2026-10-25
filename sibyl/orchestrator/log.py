"""Append-only run log in `evidence.runs` and `evidence.run_events`.

Every state change, agent step, tool call, LLM call, and decision is one
row. Payloads are redacted before they are stored. The bearer token and
other secrets are not written.
"""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg
from psycopg.types.json import Json

from sibyl.config import Settings, load_settings
from sibyl.llm.client import Receipt


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        loaded = json.loads(value)
        return loaded if isinstance(loaded, dict) else {"value": loaded}
    if isinstance(value, dict):
        return value
    return {"value": value}


class RunLog:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or load_settings()
        self.run_id: str | None = None
        self._last_ts: datetime | None = None
        self._lock = threading.Lock()

    def start(self, config: Mapping[str, Any], budget: Mapping[str, Any], *, run_id: str | None = None) -> str:
        if not self.settings.database_url:
            raise RuntimeError("missing DATABASE_URL")
        with self._lock:
            self.run_id = run_id or str(uuid.uuid4())
            self._last_ts = None
            started = self._timestamp()
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO evidence.runs (run_id, started_at, config, status, budget)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        self.run_id,
                        started,
                        Json(self._redact(dict(config))),
                        "PLANNED",
                        Json(self._redact(dict(budget))),
                    ),
                )
            self._event("orchestrator", "state", {"to": "PLANNED"})
            return self.run_id

    def event(self, actor: str, type: str, payload: Mapping[str, Any]) -> str:
        with self._lock:
            return self._event(actor, type, payload)

    def transition(self, before: str, after: str, *, actor: str = "orchestrator") -> str:
        with self._lock:
            self._set_status(after)
            return self._event(actor, "state", {"from": before, "to": after})

    def set_status(self, status: str) -> None:
        with self._lock:
            self._set_status(status)

    def _event(self, actor: str, type: str, payload: Mapping[str, Any]) -> str:
        if self.run_id is None:
            raise RuntimeError("run has not been started")
        event_id = str(uuid.uuid4())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO evidence.run_events (event_id, run_id, ts, actor, type, payload)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (event_id, self.run_id, self._timestamp(), actor, type, Json(self._redact(dict(payload)))),
            )
        return event_id

    def _set_status(self, status: str) -> None:
        if self.run_id is None:
            raise RuntimeError("run has not been started")
        with self._connect() as conn:
            conn.execute(
                "UPDATE evidence.runs SET status = %s WHERE run_id = %s",
                (status, self.run_id),
            )

    def agent_step(self, actor: str, step: str, **extra: Any) -> str:
        return self.event(actor, "agent_step", {"step": step, **extra})

    def tool_call(self, actor: str, sql: str, rows: int, ms: float) -> str:
        return self.event(actor, "tool_call", {"sql": sql, "rows": rows, "ms": ms})

    def tool(self, actor: str, sql: str, rows: int, ms: float, truncated: bool) -> str:
        """One `run_sql` call. The Run screen and the Zetaris receipt read this row."""
        return self.event(
            actor,
            "tool",
            {"sql": sql, "rows": rows, "ms": ms, "truncated": bool(truncated)},
        )

    def llm_call(self, actor: str, receipt: Receipt) -> str:
        return self.event(actor, "llm_call", receipt.model_dump())

    def decision(self, actor: str, reason: str, **extra: Any) -> str:
        return self.event(actor, "decision", {"reason": reason, **extra})

    def status(self) -> str:
        with self._lock:
            return self._status()

    def _status(self) -> str:
        if self.run_id is None:
            raise RuntimeError("run has not been started")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM evidence.runs WHERE run_id = %s",
                (self.run_id,),
            ).fetchone()
        if row is None:
            raise RuntimeError(f"run {self.run_id} is not in evidence.runs")
        return row[0]

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._events()

    def _events(self) -> list[dict[str, Any]]:
        if self.run_id is None:
            raise RuntimeError("run has not been started")
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT event_id, actor, type, payload
                FROM evidence.run_events
                WHERE run_id = %s
                ORDER BY ts ASC, event_id ASC
                """,
                (self.run_id,),
            ).fetchall()
        found: list[dict[str, Any]] = []
        for event_id, actor, event_type, payload in rows:
            found.append(
                {
                    "event_id": event_id,
                    "actor": actor,
                    "type": event_type,
                    "payload": _json_object(payload),
                }
            )
        return found

    def delete(self) -> None:
        with self._lock:
            if self.run_id is None:
                return
            with self._connect() as conn:
                conn.execute("DELETE FROM evidence.run_events WHERE run_id = %s", (self.run_id,))
                conn.execute("DELETE FROM evidence.runs WHERE run_id = %s", (self.run_id,))

    def _connect(self) -> psycopg.Connection:
        if not self.settings.database_url:
            raise RuntimeError("missing DATABASE_URL")
        return psycopg.connect(self.settings.database_url)

    def _timestamp(self) -> datetime:
        current = datetime.now(timezone.utc)
        if self._last_ts is not None and current <= self._last_ts:
            current = self._last_ts + timedelta(microseconds=1)
        self._last_ts = current
        return current

    def _redact(self, payload: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(payload, default=str)
        cleaned = self.settings.redact(encoded)
        loaded = json.loads(cleaned)
        if not isinstance(loaded, dict):
            return {"redacted": True}
        return loaded
