"""The job queue, the activity feed and the schedule state, in Postgres.

Every trigger becomes a row in `jobs.jobs`: the repository poll, a push
hook, "Sync now", a feed refresh, a triage policy, "Run now", a human
answer. A worker claims the oldest ready job of its workspace with
`FOR UPDATE SKIP LOCKED`; one worker per workspace holds that workspace's
advisory lock, so jobs of one workspace never run at the same time, in this
process or another.

A queued job with a `dedupe_key` is not queued twice. A second triage for a
workspace that already has one queued joins it: the service lists are
merged, and a whole-workspace run covers everything.

`jobs.activity` is what the activity feed shows; `jobs.schedule` remembers
when each schedule last fired.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Json

from sibyl.config import Settings, load_settings

KINDS = ("repo_sync", "feed_refresh", "triage", "memory_curate")
# Lower runs first: a person waiting beats a schedule.
PRIORITY = {"manual": 0, "answer": 0, "push": 1, "connect": 1, "on_change": 2, "schedule": 3}

DDL = """
CREATE SCHEMA IF NOT EXISTS jobs;

CREATE TABLE IF NOT EXISTS jobs.jobs (
    job_id text PRIMARY KEY,
    workspace_id text NOT NULL,
    kind text NOT NULL,
    trigger text NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'queued',
    priority integer NOT NULL DEFAULT 3,
    dedupe_key text,
    run_after timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    attempts integer NOT NULL DEFAULT 0,
    worker text NOT NULL DEFAULT '',
    run_id text,
    log_run_id text,
    result jsonb,
    error text NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS jobs_dedupe ON jobs.jobs (dedupe_key) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS jobs_ready ON jobs.jobs (workspace_id, status, priority, created_at);

CREATE TABLE IF NOT EXISTS jobs.activity (
    activity_id bigserial PRIMARY KEY,
    workspace_id text NOT NULL,
    ts timestamptz NOT NULL DEFAULT now(),
    kind text NOT NULL,
    title text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    job_id text,
    run_id text
);

CREATE INDEX IF NOT EXISTS activity_workspace ON jobs.activity (workspace_id, activity_id);

CREATE TABLE IF NOT EXISTS jobs.schedule (
    key text PRIMARY KEY,
    workspace_id text NOT NULL,
    last_at timestamptz,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb
);
"""

_ready = False


def connect(settings: Settings | None = None, **options: Any) -> psycopg.Connection:
    active = settings or load_settings()
    if not active.database_url:
        raise RuntimeError("DATABASE_URL is empty")
    return psycopg.connect(active.database_url, row_factory=dict_row, **options)


def ensure(settings: Settings | None = None) -> None:
    global _ready
    if _ready:
        return
    with connect(settings) as conn:
        conn.execute(DDL)
    _ready = True


def now() -> datetime:
    return datetime.now(timezone.utc)


def _out(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {key: value.isoformat() if isinstance(value, datetime) else value for key, value in row.items()}


# Jobs -----------------------------------------------------------------------


def enqueue(
    workspace_id: str,
    kind: str,
    *,
    trigger: str,
    payload: dict[str, Any] | None = None,
    dedupe_key: str | None = None,
    run_id: str | None = None,
    delay_seconds: float = 0,
    merge: bool = True,
    settings: Settings | None = None,
) -> tuple[dict[str, Any], bool]:
    """Queue a job. Returns (job, created). A queued job with the same key is returned instead.

    A triage joins a queued triage of the same workspace: its services are
    merged into that job's payload, and None (the whole workspace) wins.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown job kind {kind}")
    ensure(settings)
    body = dict(payload or {})
    with connect(settings) as conn:
        if kind == "triage" and merge:
            queued = conn.execute(
                "SELECT * FROM jobs.jobs WHERE workspace_id = %s AND kind = 'triage' AND status = 'queued' "
                "AND NOT (payload ? 'record_id') ORDER BY created_at LIMIT 1 FOR UPDATE",
                (workspace_id,),
            ).fetchone()
            if queued is not None:
                merged = dict(queued["payload"] or {})
                merged["services"] = _merge_services(merged.get("services"), body.get("services"))
                merged["incremental"] = bool(merged.get("incremental", True)) and bool(body.get("incremental", True))
                merged["triggers"] = sorted(set(merged.get("triggers") or [queued["trigger"]]) | {trigger})
                priority = min(int(queued["priority"]), PRIORITY.get(trigger, 3))
                row = conn.execute(
                    "UPDATE jobs.jobs SET payload = %s, priority = %s WHERE job_id = %s RETURNING *",
                    (Json(merged), priority, queued["job_id"]),
                ).fetchone()
                return _out(row), False  # type: ignore[return-value]
        if dedupe_key:
            found = conn.execute(
                "SELECT * FROM jobs.jobs WHERE dedupe_key = %s AND status = 'queued'", (dedupe_key,)
            ).fetchone()
            if found is not None:
                return _out(found), False  # type: ignore[return-value]
        job_id = "job-" + uuid.uuid4().hex[:12]
        body.setdefault("triggers", [trigger])
        row = conn.execute(
            """
            INSERT INTO jobs.jobs (job_id, workspace_id, kind, trigger, payload, priority, dedupe_key, run_after, run_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING
            RETURNING *
            """,
            (
                job_id,
                workspace_id,
                kind,
                trigger,
                Json(body),
                PRIORITY.get(trigger, 3),
                dedupe_key,
                now() + timedelta(seconds=delay_seconds),
                run_id,
            ),
        ).fetchone()
        if row is None and dedupe_key:
            found = conn.execute("SELECT * FROM jobs.jobs WHERE dedupe_key = %s AND status = 'queued'", (dedupe_key,)).fetchone()
            return _out(found), False  # type: ignore[return-value]
    return _out(row), True  # type: ignore[return-value]


def _merge_services(left: Any, right: Any) -> list[str] | None:
    if left is None or right is None:
        return None
    return sorted(set(left) | set(right))


def claim(workspace_id: str, worker: str, conn: psycopg.Connection) -> dict[str, Any] | None:
    """Take the next ready job of this workspace. The caller holds the workspace lock."""
    row = conn.cursor(row_factory=dict_row).execute(
        """
        UPDATE jobs.jobs SET status = 'running', started_at = now(), attempts = attempts + 1, worker = %s
        WHERE job_id = (
            SELECT job_id FROM jobs.jobs
            WHERE workspace_id = %s AND status = 'queued' AND run_after <= now()
            ORDER BY priority, created_at
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        RETURNING *
        """,
        (worker, workspace_id),
    ).fetchone()
    return _out(row)


def finish(job_id: str, *, status: str, result: dict[str, Any] | None = None, error: str = "", log_run_id: str | None = None, settings: Settings | None = None) -> None:
    with connect(settings) as conn:
        conn.execute(
            "UPDATE jobs.jobs SET status = %s, finished_at = now(), result = %s, error = %s, "
            "log_run_id = coalesce(%s, log_run_id) WHERE job_id = %s",
            (status, Json(result or {}), error[:1000], log_run_id, job_id),
        )


def set_log_run(job_id: str, log_run_id: str, settings: Settings | None = None) -> None:
    with connect(settings) as conn:
        conn.execute("UPDATE jobs.jobs SET log_run_id = %s WHERE job_id = %s", (log_run_id, job_id))


def get(job_id: str, settings: Settings | None = None) -> dict[str, Any] | None:
    ensure(settings)
    with connect(settings) as conn:
        return _out(conn.execute("SELECT * FROM jobs.jobs WHERE job_id = %s", (job_id,)).fetchone())


def list_jobs(workspace_id: str, *, status: str | None = None, limit: int = 50, settings: Settings | None = None) -> list[dict[str, Any]]:
    ensure(settings)
    with connect(settings) as conn:
        rows = conn.execute(
            "SELECT * FROM jobs.jobs WHERE workspace_id = %s AND (%s::text IS NULL OR status = %s) "
            "ORDER BY created_at DESC LIMIT %s",
            (workspace_id, status, status, limit),
        ).fetchall()
    return [_out(row) for row in rows]  # type: ignore[misc]


def active_jobs(workspace_id: str | None = None, settings: Settings | None = None) -> list[dict[str, Any]]:
    """Queued and running jobs, oldest first."""
    ensure(settings)
    with connect(settings) as conn:
        rows = conn.execute(
            "SELECT * FROM jobs.jobs WHERE status IN ('queued', 'running') AND (%s::text IS NULL OR workspace_id = %s) "
            "ORDER BY created_at",
            (workspace_id, workspace_id),
        ).fetchall()
    return [_out(row) for row in rows]  # type: ignore[misc]


def workspaces_with_ready_jobs(settings: Settings | None = None) -> list[str]:
    ensure(settings)
    with connect(settings) as conn:
        rows = conn.execute(
            "SELECT DISTINCT workspace_id FROM jobs.jobs WHERE status = 'queued' AND run_after <= now()"
        ).fetchall()
    return [row["workspace_id"] for row in rows]


def cancel_workspace(workspace_id: str, settings: Settings | None = None) -> int:
    ensure(settings)
    with connect(settings) as conn:
        done = conn.execute(
            "UPDATE jobs.jobs SET status = 'cancelled', finished_at = now() WHERE workspace_id = %s AND status = 'queued'",
            (workspace_id,),
        )
        return done.rowcount


def fail_running(workspace_id: str, reason: str, settings: Settings | None = None) -> int:
    """Jobs left running by a worker that is gone. The caller holds the workspace lock, so none is alive."""
    ensure(settings)
    with connect(settings) as conn:
        done = conn.execute(
            "UPDATE jobs.jobs SET status = 'failed', finished_at = now(), error = %s WHERE workspace_id = %s AND status = 'running'",
            (reason, workspace_id),
        )
        return done.rowcount


# Activity -------------------------------------------------------------------


def note(
    workspace_id: str,
    kind: str,
    title: str,
    *,
    detail: dict[str, Any] | None = None,
    job_id: str | None = None,
    run_id: str | None = None,
    settings: Settings | None = None,
) -> int:
    ensure(settings)
    with connect(settings) as conn:
        row = conn.execute(
            "INSERT INTO jobs.activity (workspace_id, kind, title, detail, job_id, run_id) "
            "VALUES (%s, %s, %s, %s, %s, %s) RETURNING activity_id",
            (workspace_id, kind, title[:300], Json(json.loads(json.dumps(detail or {}, default=str))), job_id, run_id),
        ).fetchone()
    return int(row["activity_id"])  # type: ignore[index]


def activity(workspace_id: str, *, after: int = 0, limit: int = 100, settings: Settings | None = None) -> list[dict[str, Any]]:
    ensure(settings)
    with connect(settings) as conn:
        if after:
            rows = conn.execute(
                "SELECT * FROM jobs.activity WHERE workspace_id = %s AND activity_id > %s ORDER BY activity_id LIMIT %s",
                (workspace_id, after, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM (SELECT * FROM jobs.activity WHERE workspace_id = %s ORDER BY activity_id DESC LIMIT %s) a "
                "ORDER BY activity_id",
                (workspace_id, limit),
            ).fetchall()
    return [_out(row) for row in rows]  # type: ignore[misc]


def forget_workspace(workspace_id: str, settings: Settings | None = None) -> None:
    ensure(settings)
    with connect(settings) as conn:
        conn.execute("DELETE FROM jobs.activity WHERE workspace_id = %s", (workspace_id,))
        conn.execute("DELETE FROM jobs.schedule WHERE workspace_id = %s", (workspace_id,))
        conn.execute("DELETE FROM jobs.jobs WHERE workspace_id = %s AND status <> 'running'", (workspace_id,))


# Schedule state -------------------------------------------------------------


def last_fired(key: str, settings: Settings | None = None) -> datetime | None:
    ensure(settings)
    with connect(settings) as conn:
        row = conn.execute("SELECT last_at FROM jobs.schedule WHERE key = %s", (key,)).fetchone()
    return row["last_at"] if row else None


def schedule_rows(workspace_id: str, settings: Settings | None = None) -> dict[str, dict[str, Any]]:
    ensure(settings)
    with connect(settings) as conn:
        rows = conn.execute("SELECT * FROM jobs.schedule WHERE workspace_id = %s", (workspace_id,)).fetchall()
    return {row["key"]: row for row in rows}


def fired(key: str, workspace_id: str, *, at: datetime | None = None, detail: dict[str, Any] | None = None, settings: Settings | None = None) -> None:
    ensure(settings)
    with connect(settings) as conn:
        conn.execute(
            """
            INSERT INTO jobs.schedule (key, workspace_id, last_at, detail) VALUES (%s, %s, %s, %s)
            ON CONFLICT (key) DO UPDATE SET last_at = EXCLUDED.last_at,
                detail = jobs.schedule.detail || EXCLUDED.detail
            """,
            (key, workspace_id, at or now(), Json(detail or {})),
        )
