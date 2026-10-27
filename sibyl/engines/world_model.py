"""Python client for one long-lived World Model process.

The process is the TypeScript module compiled with the `typescript`
already in `engines/`. It speaks JSON lines on stdin and stdout.

A persistent client keeps the workspace's state across restarts: each
reply's write-log entries are appended to `world.events` (one namespace per
workspace, schema-versioned), and a new process replays them on start.
A client without `persist` is memory-only: tests, the eval and the headless
runs use that, so their numbers do not depend on earlier runs. One process
at a time holds a namespace (an advisory lock), so two writers never append
the same sequence numbers.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any

import psycopg
from psycopg.types.json import Json
from pydantic import BaseModel

from sibyl.config import ROOT, Settings, load_settings
from sibyl.engines.messages import (
    AliasLink,
    Claim,
    Conflict,
    CriticDecision,
    Diff,
    DraftVerdict,
    Escalation,
    Placement,
    Priority,
    RecheckRequest,
    RunClosed,
    RunOpened,
    SourceMap,
    Verdict,
)

SERVER = ROOT / "engines" / "world-model" / "build" / "server.js"
TSC = ROOT / "engines" / "node_modules" / "typescript" / "bin" / "tsc"
TSCONFIG = ROOT / "engines" / "tsconfig.build.json"
SOURCE = ROOT / "engines" / "world-model" / "src"
# Entries replayed per request on start.
REPLAY_CHUNK = 2000

WORLD_DDL = """
CREATE SCHEMA IF NOT EXISTS world;

CREATE TABLE IF NOT EXISTS world.events (
    namespace text NOT NULL,
    seq bigint NOT NULL,
    schema_version integer NOT NULL,
    op text NOT NULL,
    at text NOT NULL,
    body jsonb NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace, seq)
);

CREATE TABLE IF NOT EXISTS world.case_state (
    workspace_id text NOT NULL,
    case_id text NOT NULL,
    service_id text NOT NULL,
    package text NOT NULL DEFAULT '',
    version text NOT NULL DEFAULT '',
    ecosystem text NOT NULL DEFAULT '',
    purl text NOT NULL DEFAULT '',
    vuln_id text NOT NULL DEFAULT '',
    verdict text NOT NULL,
    placement text NOT NULL,
    status text NOT NULL,
    score double precision NOT NULL DEFAULT 0,
    confidence double precision NOT NULL DEFAULT 0,
    resolution text NOT NULL DEFAULT '',
    exploited boolean NOT NULL DEFAULT false,
    epss_percentile double precision NOT NULL DEFAULT 0,
    cvss double precision NOT NULL DEFAULT 0,
    run_id text NOT NULL,
    reused_from text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, case_id)
);

CREATE INDEX IF NOT EXISTS case_state_service ON world.case_state (service_id, status);
"""


def ensure_world_schema(conn: psycopg.Connection) -> None:
    conn.execute(WORLD_DDL)


def drop_namespace(namespace: str, settings: Settings | None = None) -> None:
    """Forget a workspace's World Model: its event log and its case state."""
    active = settings or load_settings()
    if not active.database_url:
        return
    with psycopg.connect(active.database_url) as conn:
        ensure_world_schema(conn)
        conn.execute("DELETE FROM world.events WHERE namespace = %s", (namespace,))
        conn.execute("DELETE FROM world.case_state WHERE workspace_id = %s", (namespace,))


def compile_world_model() -> Path:
    """Emit `server.js` when sources are newer than the last build."""
    if not TSC.is_file():
        raise RuntimeError("typescript is not installed in engines/; npm install there, not tsx")
    newest = max(path.stat().st_mtime for path in SOURCE.glob("*.ts"))
    if SERVER.is_file() and SERVER.stat().st_mtime >= newest:
        return SERVER
    subprocess.run([str(TSC), "-p", str(TSCONFIG)], check=True, cwd=ROOT / "engines")
    if not SERVER.is_file():
        raise RuntimeError("typescript did not emit the world model server")
    return SERVER


class WorldModelClient:
    def __init__(self, namespace: str = "sibyl", *, persist: bool = False, settings: Settings | None = None) -> None:
        server = compile_world_model()
        self.namespace = namespace
        env = os.environ.copy()
        env["WM_NAMESPACE"] = namespace
        self._proc = subprocess.Popen(
            ["node", str(server)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env=env,
            text=True,
            bufsize=1,
        )
        self._lock = threading.Lock()
        self._next = 0
        self._closed = False
        self._db: psycopg.Connection | None = None
        self.replayed = 0
        if persist:
            try:
                self._open_store(settings or load_settings())
            except Exception:
                self.close()
                raise

    @property
    def persistent(self) -> bool:
        return self._db is not None

    def _open_store(self, settings: Settings) -> None:
        if not settings.database_url:
            raise RuntimeError("a persistent World Model needs DATABASE_URL")
        from sibyl.jobs.locks import lock_key

        self._db = psycopg.connect(settings.database_url, autocommit=True)
        held = self._db.execute("SELECT pg_try_advisory_lock(%s)", (lock_key(f"world:{self.namespace}"),)).fetchone()
        if not (held and held[0]):
            self._db.close()
            self._db = None
            raise RuntimeError(f"the World Model of {self.namespace} is open in another Sibyl process")
        ensure_world_schema(self._db)
        last = 0
        while True:
            rows = self._db.execute(
                "SELECT seq, schema_version, op, at, body FROM world.events "
                "WHERE namespace = %s AND seq > %s ORDER BY seq LIMIT %s",
                (self.namespace, last, REPLAY_CHUNK),
            ).fetchall()
            if not rows:
                break
            entries = [{"seq": int(seq), "v": int(version), "op": op, "at": at, "input": body} for seq, version, op, at, body in rows]
            self._request("replay", {"entries": entries})
            self.replayed += len(entries)
            last = int(rows[-1][0])

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._proc.poll() is None:
                self._request("close", {})
        finally:
            if self._proc.poll() is None:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            if self._db is not None:
                self._db.close()
                self._db = None

    def __enter__(self) -> WorldModelClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def claim(self, message: Claim) -> Diff:
        return self._apply("claim", message)

    def alias_link(self, message: AliasLink) -> Diff:
        return self._apply("alias_link", message)

    def source_map(self, message: SourceMap) -> Diff:
        return self._apply("source_map", message)

    def draft_verdict(self, message: DraftVerdict) -> Diff:
        return self._apply("draft_verdict", message)

    def conflict(self, message: Conflict) -> Diff:
        return self._apply("conflict", message)

    def recheck_request(self, message: RecheckRequest) -> Diff:
        return self._apply("recheck_request", message)

    def critic_decision(self, message: CriticDecision) -> Diff:
        return self._apply("critic_decision", message)

    def verdict(self, message: Verdict) -> Diff:
        return self._apply("verdict", message)

    def priority(self, message: Priority) -> Diff:
        return self._apply("priority", message)

    def escalation(self, message: Escalation) -> Diff:
        return self._apply("escalation", message)

    def run_opened(self, message: RunOpened) -> Diff:
        return self._apply("run_opened", message)

    def placement(self, message: Placement) -> Diff:
        return self._apply("placement", message)

    def run_closed(self, message: RunClosed) -> Diff:
        return self._apply("run_closed", message)

    def write(self, messages: list[tuple[str, BaseModel]]) -> list[Diff]:
        """Several messages in one round trip, as (method, message) pairs."""
        if not messages:
            return []
        items = [{"method": method, "payload": message.model_dump(by_alias=True)} for method, message in messages]
        result = self._request("batch", {"items": items})
        return [Diff.model_validate(item) for item in result]

    def case(self, case_id: str, run_id: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"case_id": case_id}
        if run_id is not None:
            payload["run_id"] = run_id
        result = self._request("case", payload)
        if not isinstance(result, dict):
            raise RuntimeError("case projection was not an object")
        return result

    def cases(self, case_ids: list[str], run_id: str | None = None) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {"case_ids": list(case_ids)}
        if run_id is not None:
            payload["run_id"] = run_id
        result = self._request("cases", payload)
        if not isinstance(result, list):
            raise RuntimeError("case projections were not a list")
        return result

    def ingest(self, observations: list[dict[str, Any]]) -> dict[str, Any]:
        result = self._request("ingest", {"observations": observations})
        if not isinstance(result, dict):
            raise RuntimeError("ingest did not return an object")
        return result

    def relate(self, *, from_id: str, type: str, to: str, valid_from: str, source: dict[str, Any], slot: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"from": from_id, "type": type, "to": to, "validFrom": valid_from, "source": source}
        if slot is not None:
            payload["slot"] = slot
        return self._request("relate", payload)

    def unrelate(self, *, from_id: str, type: str, valid_to: str, source: dict[str, Any], slot: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"from": from_id, "type": type, "validTo": valid_to, "source": source}
        if slot is not None:
            payload["slot"] = slot
        return self._request("unrelate", payload)

    def edges(self, from_id: str, *, via: str | None = None, slot: str | None = None, at: str | None = None) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {"from": from_id}
        for key, value in (("via", via), ("slot", slot), ("at", at)):
            if value is not None:
                payload[key] = value
        result = self._request("edges", payload)
        return result if isinstance(result, list) else []

    def report(self, run_id: str | None = None) -> dict[str, Any] | None:
        result = self._request("report", {"run_id": run_id} if run_id else {})
        return result if isinstance(result, dict) else None

    def runs(self) -> list[dict[str, Any]]:
        result = self._request("runs", {})
        return result if isinstance(result, list) else []

    def current_cases(self) -> list[dict[str, Any]]:
        result = self._request("current_cases", {})
        return result if isinstance(result, list) else []

    def _apply(self, method: str, message: BaseModel) -> Diff:
        result = self._request(method, message.model_dump(by_alias=True))
        return Diff.model_validate(result)

    def _request(self, method: str, payload: dict[str, Any]) -> Any:
        if self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("world model process is not running")
        with self._lock:
            self._next += 1
            ident = str(self._next)
            self._proc.stdin.write(json.dumps({"id": ident, "method": method, "payload": payload}) + "\n")
            self._proc.stdin.flush()
            line = self._proc.stdout.readline()
            if line == "":
                raise RuntimeError("world model process closed")
            message = json.loads(line)
            # Durable before the next request: the log order is the replay order.
            if message.get("log") and self._db is not None:
                self._persist(message["log"])
        if message.get("id") != ident:
            raise RuntimeError("world model reply did not match the request")
        if not message.get("ok"):
            raise RuntimeError(str(message.get("error") or "world model error"))
        return message.get("result")

    def _persist(self, entries: list[dict[str, Any]]) -> None:
        assert self._db is not None
        with self._db.cursor() as cur:
            cur.executemany(
                "INSERT INTO world.events (namespace, seq, schema_version, op, at, body) "
                "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (namespace, seq) DO NOTHING",
                [
                    (self.namespace, int(entry["seq"]), int(entry["v"]), str(entry["op"]), str(entry["at"]), Json(entry["input"]))
                    for entry in entries
                ],
            )
