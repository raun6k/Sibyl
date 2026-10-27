"""The scheduler and the workers, inside the API process.

Every `tick` seconds the scheduler queues what is due (D25 defaults, all
editable):

- `repo_sync`: each repository is polled every `sync_interval_minutes`
  (default 60) with `git ls-remote` (a local folder reads its HEAD); a new
  tip queues a sync. A push hook and "Sync now" queue one directly.
- `feed_refresh`: each live workspace every `feed_refresh_minutes` from its
  settings (default 1440).
- `triage`: each `interval` service every `triage_interval_minutes`
  (default 1440); due services of one workspace share one job.

The demo workspace has no automatic triggers: it replays a frozen snapshot,
so a schedule would only repeat it. "Run now" works there.

Workers: one thread per workspace with ready jobs, holding that workspace's
advisory lock, claiming jobs one at a time. It exits after a short idle.
"""

from __future__ import annotations

import os
import socket
import threading
import time
import traceback
from datetime import datetime, timedelta
from typing import Any

from sibyl.config import Settings, load_settings
from sibyl.inventory import store
from sibyl.jobs import queue
from sibyl.jobs.handlers import Engines, run_job
from sibyl.jobs.locks import try_worker_lock

DEFAULT_FEED_MINUTES = 1440
IDLE_SECONDS = 20


def next_times(workspace: dict[str, Any], settings: Settings | None = None) -> dict[str, Any]:
    """When each schedule of a workspace last fired and fires next, for the UI."""
    workspace_id = workspace["workspace_id"]
    rows = queue.schedule_rows(workspace_id, settings)
    automatic = not workspace.get("is_demo")

    def last(key: str) -> datetime | None:
        row = rows.get(key)
        return row["last_at"] if row else None

    def iso(value: datetime | None) -> str | None:
        return value.isoformat() if value is not None else None

    repos = []
    for repo in store.list_repositories(workspace_id, settings):
        fired = last(f"repo:{repo['repo_id']}")
        interval = int(repo.get("sync_interval_minutes") or 60)
        repos.append(
            {
                "repo_id": repo["repo_id"],
                "interval_minutes": interval,
                "last_poll": iso(fired),
                "next_poll": iso((fired + timedelta(minutes=interval)) if fired else queue.now()) if automatic else None,
                "detail": (rows.get(f"repo:{repo['repo_id']}") or {}).get("detail") or {},
            }
        )
    feed_minutes = feed_interval(workspace)
    feed_last = last(f"feed:{workspace_id}")
    services = []
    for service in store.list_services(workspace_id, settings):
        policy = service.get("triage_policy") or "interval"
        interval = int(service.get("triage_interval_minutes") or 1440)
        fired = last(f"triage:{service['service_id']}")
        if not automatic or policy == "manual":
            upcoming = None
        elif policy == "on_change":
            upcoming = "after the next change"
        else:
            upcoming = iso(fired + timedelta(minutes=interval)) if fired else "after its first scan"
        services.append(
            {
                "service_id": service["service_id"],
                "policy": policy,
                "interval_minutes": interval,
                "last_triage": iso(fired),
                "next_run": upcoming,
            }
        )
    return {
        "automatic": automatic,
        "repositories": repos,
        "feed": {
            "interval_minutes": feed_minutes,
            "last_refresh": iso(feed_last),
            "next_refresh": iso(feed_last + timedelta(minutes=feed_minutes)) if (automatic and feed_last) else (iso(queue.now()) if automatic else None),
        },
        "services": services,
    }


def feed_interval(workspace: dict[str, Any]) -> int:
    configured = (workspace.get("settings") or {}).get("feed_refresh_minutes")
    try:
        return max(60, int(configured)) if configured else DEFAULT_FEED_MINUTES
    except (TypeError, ValueError):
        return DEFAULT_FEED_MINUTES


class Scheduler:
    def __init__(self, engines: Engines, settings: Settings | None = None, *, tick: float = 30, automatic: bool = True) -> None:
        self.engines = engines
        self.settings = settings or load_settings()
        self.tick_seconds = tick
        self.automatic = automatic
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._workers: dict[str, threading.Thread] = {}
        self._lock = threading.Lock()
        self.name = f"{socket.gethostname()}:{os.getpid()}"
        self.last_error = ""

    def start(self) -> None:
        queue.ensure(self.settings)
        self._thread = threading.Thread(target=self._loop, name="sibyl-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def wake(self) -> None:
        """Start workers now, after something was queued."""
        self._wake.set()

    def _loop(self) -> None:
        next_tick = 0.0
        while not self._stop.is_set():
            try:
                if self.automatic and time.monotonic() >= next_tick:
                    self.tick()
                    next_tick = time.monotonic() + self.tick_seconds
                self.dispatch()
            except Exception as exc:  # the loop must survive a bad tick
                self.last_error = f"{exc}"
                traceback.print_exc()
            self._wake.wait(timeout=2)
            self._wake.clear()

    # What is due ----------------------------------------------------------

    def tick(self) -> None:
        for workspace in store.list_workspaces(self.settings):
            if workspace.get("is_demo"):
                continue
            try:
                self._repos(workspace)
                self._feeds(workspace)
                self._triage(workspace)
            except Exception as exc:
                self.last_error = f"{workspace['workspace_id']}: {exc}"

    def _repos(self, workspace: dict[str, Any]) -> None:
        from sibyl.repos.source import open_source

        busy = {
            (job.get("payload") or {}).get("repo_id")
            for job in queue.active_jobs(workspace["workspace_id"], self.settings)
            if job["kind"] == "repo_sync"
        }
        for repo in store.list_repositories(workspace["workspace_id"], self.settings):
            key = f"repo:{repo['repo_id']}"
            interval = timedelta(minutes=int(repo.get("sync_interval_minutes") or 60))
            fired = queue.last_fired(key, self.settings)
            if fired is not None and queue.now() - fired < interval:
                continue
            if repo["repo_id"] in busy:
                continue
            head = ""
            try:
                head = open_source(repo, self.settings).remote_head()
            except Exception:
                head = ""
            queue.fired(key, workspace["workspace_id"], detail={"remote_head": head, "polled": True}, settings=self.settings)
            if head and head == repo.get("last_scanned_sha") and repo.get("status") != "error":
                continue
            queue.enqueue(
                workspace["workspace_id"],
                "repo_sync",
                trigger="schedule",
                payload={"repo_id": repo["repo_id"], "remote_head": head},
                dedupe_key=f"repo_sync:{repo['repo_id']}",
                settings=self.settings,
            )

    def _feeds(self, workspace: dict[str, Any]) -> None:
        if not workspace.get("services"):
            return
        key = f"feed:{workspace['workspace_id']}"
        fired = queue.last_fired(key, self.settings)
        if fired is not None and queue.now() - fired < timedelta(minutes=feed_interval(workspace)):
            return
        queue.fired(key, workspace["workspace_id"], detail={"queued": True}, settings=self.settings)
        queue.enqueue(
            workspace["workspace_id"],
            "feed_refresh",
            trigger="schedule",
            dedupe_key=f"feed:{workspace['workspace_id']}",
            settings=self.settings,
        )

    def _triage(self, workspace: dict[str, Any]) -> None:
        workspace_id = workspace["workspace_id"]
        active = queue.active_jobs(workspace_id, self.settings)
        if any(job["kind"] == "repo_sync" for job in active):
            return  # the sync queues what it changed; the clock waits for it
        covered: set[str] = set()
        for job in active:
            if job["kind"] != "triage":
                continue
            services = (job.get("payload") or {}).get("services")
            if services is None:
                return
            covered.update(services)
        due = []
        for service in store.list_services(workspace_id, self.settings):
            if (service.get("triage_policy") or "interval") != "interval" or service["service_id"] in covered:
                continue
            if not int(service.get("components") or 0):
                continue
            fired = queue.last_fired(f"triage:{service['service_id']}", self.settings)
            interval = timedelta(minutes=int(service.get("triage_interval_minutes") or 1440))
            if fired is None or queue.now() - fired >= interval:
                due.append(service["service_id"])
        if due:
            queue.enqueue(
                workspace_id,
                "triage",
                trigger="schedule",
                payload={"services": sorted(due), "incremental": True, "reason": "interval", "window": "quiet"},
                settings=self.settings,
            )

    # Workers --------------------------------------------------------------

    def dispatch(self) -> None:
        for workspace_id in queue.workspaces_with_ready_jobs(self.settings):
            with self._lock:
                worker = self._workers.get(workspace_id)
                if worker is not None and worker.is_alive():
                    continue
                thread = threading.Thread(target=self._work, args=(workspace_id,), name=f"sibyl-worker-{workspace_id}", daemon=True)
                self._workers[workspace_id] = thread
                thread.start()

    def busy(self, workspace_id: str) -> bool:
        with self._lock:
            worker = self._workers.get(workspace_id)
            return worker is not None and worker.is_alive()

    def _work(self, workspace_id: str) -> None:
        conn = try_worker_lock(workspace_id, self.settings)
        if conn is None:
            return  # another process works this workspace
        name = f"{self.name}:{threading.get_ident()}"
        try:
            queue.fail_running(workspace_id, "the worker stopped before the job finished (API restart)", self.settings)
            idle_since = time.monotonic()
            while not self._stop.is_set():
                try:
                    job = queue.claim(workspace_id, name, conn)
                except Exception as exc:  # a broken claim ends this worker; the next dispatch starts another
                    self.last_error = f"claim {workspace_id}: {exc}"
                    return
                if job is None:
                    if time.monotonic() - idle_since > IDLE_SECONDS:
                        return
                    time.sleep(1)
                    continue
                self._run(job)
                idle_since = time.monotonic()
        finally:
            conn.close()

    def _run(self, job: dict[str, Any]) -> None:
        queue.note(job["workspace_id"], "job_started", f"{_label(job)} started", detail={"trigger": job["trigger"]}, job_id=job["job_id"], settings=self.settings)
        try:
            result = run_job(job, self.engines, self.settings)
        except Exception as exc:
            message = self.settings.redact(str(exc))[:1000]
            queue.finish(job["job_id"], status="failed", error=message, settings=self.settings)
            queue.note(job["workspace_id"], "job_failed", f"{_label(job)} failed: {message[:200]}", job_id=job["job_id"], settings=self.settings)
            return
        queue.finish(job["job_id"], status="done", result=result, log_run_id=result.get("log_run_id"), settings=self.settings)


def _label(job: dict[str, Any]) -> str:
    payload = job.get("payload") or {}
    if job["kind"] == "repo_sync":
        return f"Sync of {payload.get('repo_id')}"
    if job["kind"] == "feed_refresh":
        return "Feed refresh"
    if job["kind"] == "triage":
        services = payload.get("services")
        return "Triage of " + ("all services" if services is None else ", ".join(services))
    return "Memory curation"
