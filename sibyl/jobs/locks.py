"""Postgres advisory locks that keep background work apart.

- One worker per workspace: `worker_lock` is held for the worker's life.
- Evidence: the evidence tables are a cache shared by every workspace. A
  demo run empties them and loads its snapshot, so it holds the evidence
  lock alone (exclusive); live feed refreshes and live triages hold it
  shared. A live workspace is never read while the demo resets evidence,
  and the demo never sees rows a live ingest wrote. After a demo run, the
  next live triage re-ingests its workspace's advisories first.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg

from sibyl.config import Settings, load_settings


class LockTimeout(RuntimeError):
    pass


def lock_key(name: str) -> int:
    """A signed 64-bit key from a name, the same in every process."""
    return int.from_bytes(hashlib.sha256(f"sibyl:{name}".encode()).digest()[:8], "big", signed=True)


def _connect(settings: Settings | None) -> psycopg.Connection:
    active = settings or load_settings()
    return psycopg.connect(active.database_url, autocommit=True)


def try_worker_lock(workspace_id: str, settings: Settings | None = None) -> psycopg.Connection | None:
    """The workspace's worker lock on its own connection, or None when another worker has it."""
    conn = _connect(settings)
    held = conn.execute("SELECT pg_try_advisory_lock(%s)", (lock_key(f"worker:{workspace_id}"),)).fetchone()
    if held and held[0]:
        return conn
    conn.close()
    return None


@contextmanager
def evidence_lock(*, exclusive: bool, wait_seconds: float = 3600, settings: Settings | None = None) -> Iterator[None]:
    """Hold the evidence lock: exclusive for a demo run, shared for live work."""
    conn = _connect(settings)
    key = lock_key("evidence")
    take = "SELECT pg_try_advisory_lock(%s)" if exclusive else "SELECT pg_try_advisory_lock_shared(%s)"
    release = "SELECT pg_advisory_unlock(%s)" if exclusive else "SELECT pg_advisory_unlock_shared(%s)"
    deadline = time.monotonic() + wait_seconds
    try:
        while True:
            got = conn.execute(take, (key,)).fetchone()
            if got and got[0]:
                break
            if time.monotonic() >= deadline:
                raise LockTimeout("evidence is in use by a demo run" if not exclusive else "evidence is in use by live work")
            time.sleep(1)
        try:
            yield
        finally:
            conn.execute(release, (key,))
    finally:
        conn.close()
