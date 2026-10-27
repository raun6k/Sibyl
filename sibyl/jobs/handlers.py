"""What each background job does.

Every job opens its own run log (`evidence.runs` / `run_events`), so the
trace, the SSE stream and the receipts work for background work the same
way they work for a triage someone started. Each job also writes a line or
two to the workspace's activity feed, and queues the work it unblocks:

- `repo_sync` → a triage of the services whose components changed;
- `feed_refresh` → a triage of the services whose advisories changed;
- `triage` → the case state in Postgres, and the inbox;
- `memory_curate` → pending trust proposals, and a triage of the answered case's service.

A triage follows each service's policy: `on_change` services are queued
after a sync or a refresh touched them, `interval` services by the clock
(and once right after their first scan), `manual` services only on "Run now".
"""

from __future__ import annotations

import json
import sys
import time
from collections import Counter
from datetime import timedelta
from typing import Any, Protocol

from sibyl.config import ROOT, Settings, load_settings
from sibyl.inventory import store
from sibyl.jobs import queue
from sibyl.jobs.locks import evidence_lock
from sibyl.orchestrator.log import RunLog
from sibyl.orchestrator.receipts import LoggingLLM, remember_calls

DATASETS = {
    "fixtures": ROOT / "tests" / "fixtures" / "snapshots",
    "subset": ROOT / "data" / "sample" / "snapshot-subset",
    "full": ROOT / "data" / "sample" / "snapshots",
}
# A live triage re-reads its advisories unless a feed refresh after the last sync and the last demo reset is this fresh.
FRESH_FEEDS = timedelta(hours=6)
EVIDENCE_RESET = "evidence:reset"


class Engines(Protocol):
    runs: dict[str, dict[str, Any]]
    order: list[str]

    def hmem_for(self, workspace_id: str) -> Any: ...

    def world_for(self, workspace_id: str) -> Any: ...

    def new_run_record(self, workspace_id: str, **fields: Any) -> dict[str, Any]: ...

    def save_run(self, record: dict[str, Any]) -> None: ...


def _scripts() -> None:
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))


def run_job(job: dict[str, Any], engines: Engines, settings: Settings | None = None) -> dict[str, Any]:
    """Run one claimed job. Returns its result; raises when it failed."""
    active = settings or load_settings()
    kind = job["kind"]
    if kind == "repo_sync":
        return repo_sync(job, engines, active)
    if kind == "feed_refresh":
        return feed_refresh(job, engines, active)
    if kind == "triage":
        return triage(job, engines, active)
    if kind == "memory_curate":
        return memory_curate(job, engines, active)
    raise ValueError(f"unknown job kind {kind}")


def _job_log(job: dict[str, Any], settings: Settings, **config: Any) -> RunLog:
    log = RunLog(settings)
    log.start(
        {"kind": job["kind"], "job_id": job["job_id"], "workspace_id": job["workspace_id"], "trigger": job["trigger"], **config},
        {"max_tokens": settings.run_max_tokens, "max_seconds": settings.run_max_seconds},
    )
    queue.set_log_run(job["job_id"], log.run_id or "", settings)
    return log


def _llm(settings: Settings, log: RunLog | None):
    from sibyl.llm.client import LLMClient

    if not settings.meterless_runtime_token:
        return None, None
    client = LLMClient(settings)
    return client, LoggingLLM(client, log)


# Repository sync --------------------------------------------------------------


def repo_sync(job: dict[str, Any], engines: Engines, settings: Settings) -> dict[str, Any]:
    from sibyl.repos.sync import sync_repository

    payload = job["payload"] or {}
    repo_id = str(payload.get("repo_id") or "")
    repo = store.get_repository(repo_id, settings)
    workspace_id = repo["workspace_id"]
    log = _job_log(job, settings, repo_id=repo_id, full=bool(payload.get("full")))
    log.transition("PLANNED", "SYNCING")
    client, speaker = _llm(settings, log)
    try:
        summary = sync_repository(
            repo_id,
            settings,
            hmem=engines.hmem_for(workspace_id),
            llm=speaker,
            force_full=bool(payload.get("full")),
            world=engines.world_for(workspace_id),
        )
    finally:
        if client is not None:
            client.close()
    queue.fired(f"repo:{repo_id}", workspace_id, detail={"head": repo.get("last_scanned_sha"), "synced": True}, settings=settings)
    changed = _changed_services(summary)
    log.event("repo_sync", "summary", {key: summary.get(key) for key in ("mode", "seconds", "questions", "new_services", "edges", "error")} | {"changed_services": changed})
    if summary.get("error"):
        log.transition("SYNCING", "FAILED")
        queue.note(workspace_id, "sync_failed", f"Sync of {repo_id} failed: {summary['error']}", job_id=job["job_id"], run_id=log.run_id, settings=settings)
        raise RuntimeError(str(summary["error"]))
    title = f"Synced {repo_id} ({summary.get('mode')})"
    if changed:
        title += f": {len(changed)} services changed"
    if summary.get("questions"):
        title += f", {summary['questions']} new questions"
    queue.note(workspace_id, "sync", title, detail={"mode": summary.get("mode"), "changed": changed, "questions": summary.get("questions", 0)}, job_id=job["job_id"], run_id=log.run_id, settings=settings)
    if summary.get("questions"):
        queue.note(workspace_id, "questions", f"{summary['questions']} questions about {repo_id} are in the inbox", job_id=job["job_id"], settings=settings)
    follow = after_change(workspace_id, changed, trigger="on_change", reason=f"sync of {repo_id}", settings=settings)
    log.transition("SYNCING", "DONE")
    return {"mode": summary.get("mode"), "changed": changed, "questions": summary.get("questions", 0), "triage": follow, "log_run_id": log.run_id}


def _changed_services(summary: dict[str, Any]) -> list[str]:
    changed = set()
    for service_id, diff in (summary.get("services") or {}).items():
        if any(int(diff.get(key) or 0) for key in ("added", "removed", "changed")):
            changed.add(service_id)
    for item in summary.get("new_services") or []:
        changed.add(item.get("service_id"))
    return sorted(name for name in changed if name)


def after_change(workspace_id: str, service_ids: list[str], *, trigger: str, reason: str, settings: Settings) -> dict[str, Any] | None:
    """Queue a triage for the changed services whose policy asks for one.

    `on_change` services always; `interval` services only before their
    first triage, so a newly connected repository is triaged on its own.
    """
    if not service_ids:
        return None
    wanted = set(service_ids)
    due = []
    for service in store.list_services(workspace_id, settings):
        if service["service_id"] not in wanted:
            continue
        policy = service.get("triage_policy") or "interval"
        if policy == "on_change":
            due.append(service["service_id"])
        elif policy == "interval" and queue.last_fired(f"triage:{service['service_id']}", settings) is None:
            due.append(service["service_id"])
    if not due:
        return None
    job, _created = queue.enqueue(
        workspace_id,
        "triage",
        trigger=trigger,
        payload={"services": sorted(due), "incremental": True, "reason": reason, "window": "now"},
        settings=settings,
    )
    return {"job_id": job["job_id"], "services": sorted(due)}


# Feed refresh ---------------------------------------------------------------


def feed_refresh(job: dict[str, Any], engines: Engines, settings: Settings) -> dict[str, Any]:
    workspace_id = job["workspace_id"]
    workspace = store.get_workspace(workspace_id, settings)
    log = _job_log(job, settings)
    log.transition("PLANNED", "COLLECTING")
    if workspace["is_demo"]:
        log.decision("collector", "the demo workspace reads its frozen snapshots; nothing to refresh")
        log.transition("COLLECTING", "DONE")
        return {"skipped": "demo"}
    live = settings.model_copy(update={"sample_mode": False, "workspace_id": workspace_id})
    with evidence_lock(exclusive=False, settings=settings):
        before = service_digests(workspace_id, settings)
        reports = _ingest_live(live, log)
        after = service_digests(workspace_id, settings)
    queue.fired(f"feed:{workspace_id}", workspace_id, detail={"refreshed": True}, settings=settings)
    touched = sorted(name for name in after if after.get(name) != before.get(name))
    counts = {item["source"]: item for item in reports}
    new = sum(int(item.get("new") or 0) for item in reports)
    changed = sum(int(item.get("changed") or 0) for item in reports)
    queue.note(
        workspace_id,
        "feeds",
        f"Advisory feeds refreshed: {new} new, {changed} changed records; {len(touched)} services touched",
        detail={"sources": counts, "touched": touched},
        job_id=job["job_id"],
        run_id=log.run_id,
        settings=settings,
    )
    follow = after_change(workspace_id, touched, trigger="on_change", reason="feed refresh", settings=settings)
    log.transition("COLLECTING", "DONE")
    return {"new": new, "changed": changed, "touched": touched, "triage": follow, "log_run_id": log.run_id}


def _ingest_live(settings: Settings, log: RunLog | None) -> list[dict[str, Any]]:
    """Fetch this workspace's advisories, then rebuild the EPSS tables if the CVE set changed."""
    from sibyl.tools.collectors import ingest_workspace
    from sibyl.tools.epss_refresh import refresh_epss

    reports = []
    for item in ingest_workspace(settings.workspace_id, settings):
        entry = {
            "source": item.source,
            "new": getattr(item, "new", 0),
            "changed": getattr(item, "changed", 0),
            "unchanged": getattr(item, "unchanged", 0),
            "degraded": bool(getattr(item, "degraded", False)),
            "errors": list(getattr(item, "errors", []) or [])[:5],
        }
        reports.append(entry)
        if log is not None and log.run_id:
            log.event("collector", "ingest", entry)
    epss = refresh_epss(settings)
    if log is not None and log.run_id:
        log.event("collector", "epss_tables", epss)
    queue.fired(f"feed:{settings.workspace_id}", settings.workspace_id, detail={"refreshed": True}, settings=settings)
    return reports


def service_digests(workspace_id: str, settings: Settings) -> dict[str, str]:
    """One hash per service over the advisory records that name its packages."""
    with store.connect(settings) as conn:
        rows = conn.execute(
            """
            SELECT s.service_id,
                   md5(coalesce(string_agg(r.record_id || ':' || coalesce(r.content_hash, ''), ',' ORDER BY r.record_id), '')) AS digest
            FROM inventory.services s
            JOIN inventory.sboms b ON b.service_id = s.service_id
            JOIN inventory.components c ON c.sbom_id = b.sbom_id
            LEFT JOIN evidence.affected a ON a.ecosystem = c.ecosystem AND a.package = c.name
            LEFT JOIN evidence.source_records r ON r.record_id = a.record_id
            WHERE s.workspace_id = %s AND s.status = 'active'
            GROUP BY s.service_id
            """,
            (workspace_id,),
        ).fetchall()
    return {row["service_id"]: row["digest"] for row in rows}


# Triage ---------------------------------------------------------------------


def triage(job: dict[str, Any], engines: Engines, settings: Settings) -> dict[str, Any]:
    _scripts()
    from run_demo import _bundles, _prepare

    from sibyl.engines.case_state import project_case_state
    from sibyl.inventory.edges import demo_edges
    from sibyl.orchestrator.incremental import Planner
    from sibyl.orchestrator.run import run_triage
    from sibyl.tools.zetaris import tracing_sql

    payload = job["payload"] or {}
    workspace_id = job["workspace_id"]
    workspace = store.get_workspace(workspace_id, settings)
    live = not workspace["is_demo"]
    dataset = "live" if live else str(payload.get("dataset") or "subset")
    if not live and dataset not in DATASETS:
        raise ValueError("dataset must be fixtures, subset, or full")
    services = payload.get("services")
    incremental = bool(payload.get("incremental", True))
    disabled = [str(name) for name in payload.get("disable_sources") or []]
    record = engines.runs.get(str(payload.get("record_id") or "")) if payload.get("record_id") else None
    if record is None:
        record = engines.new_run_record(
            workspace_id,
            dataset=dataset,
            window_days=int(payload.get("window_days") or 14),
            disable_sources=disabled,
        )
    record.update({"status": "RUNNING", "stage": "PLANNED", "job_id": job["job_id"], "trigger": job["trigger"], "services": services, "incremental": incremental})
    update: dict[str, Any] = {"workspace_id": workspace_id, "disable_sources": ",".join(disabled)}
    if live:
        update["sample_mode"] = False
    else:
        update.update({"sample_mode": True, "snapshot_dir": str(DATASETS[dataset])})
    active = settings.model_copy(update=update)
    hmem = engines.hmem_for(workspace_id)
    world = engines.world_for(workspace_id)
    log: RunLog | None = None
    try:
        with evidence_lock(exclusive=not live, settings=settings):
            if live:
                if _needs_ingest(workspace_id, settings):
                    _ingest_live(active, None)
            else:
                # The demo resets evidence to its snapshot, so its results stay reproducible.
                _prepare(active)
                queue.fired(EVIDENCE_RESET, workspace_id, settings=settings)
                demo_edges(world, workspace_id, settings)
            log = RunLog(active)
            log.start(
                {
                    "kind": "triage",
                    "workspace_id": workspace_id,
                    "dataset": dataset,
                    "window_days": record.get("window_days"),
                    "disable_sources": disabled,
                    "job_id": job["job_id"],
                    "trigger": job["trigger"],
                    "services": services,
                    "incremental": incremental,
                },
                {"max_tokens": active.run_max_tokens, "max_seconds": active.run_max_seconds},
            )
            queue.set_log_run(job["job_id"], log.run_id or "", settings)
            record["log"] = log
            client, speaker = _llm(active, log)
            if client is None:
                raise RuntimeError("METERLESS_RUNTIME_TOKEN is empty")
            try:
                zetaris: list[dict[str, Any]] = []
                log.transition("PLANNED", "COLLECTING")
                record["stage"] = "COLLECTING"
                planner = Planner(world, active, hmem, log.run_id or "", incremental=incremental)
                with tracing_sql(log, zetaris):
                    cases = _bundles(
                        active,
                        speaker,
                        sorted(active.disabled_sources()),
                        None,
                        hmem,
                        trace=log,
                        services=set(services) if services is not None else None,
                        planner=planner,
                    )
                batch = RationaleBatch(active, log, speaker.receipts, window=str(payload.get("window") or ("quiet" if job["trigger"] == "schedule" else "now")))
                report = run_triage(
                    cases,
                    settings=active,
                    llm=speaker,
                    log=log,
                    hmem=hmem,
                    world=world,
                    precollected=True,
                    incremental=incremental,
                    services=services,
                    receipts={"zetaris": zetaris, "llm": speaker.receipts},
                    rationale_batch=batch,
                )
            finally:
                client.close()
        rows = project_case_state(world, workspace_id, active)
        record["report"] = json.loads(report.model_dump_json())
        record["status"] = report.state
        record["stage"] = report.state
        record["finished"] = time.time()
        record["reused"] = len(report.reused)
        scope = services if services is not None else [item["service_id"] for item in store.list_services(workspace_id, settings)]
        for service_id in scope:
            queue.fired(f"triage:{service_id}", workspace_id, detail={"run_id": record["id"]}, settings=settings)
        _note_triage(workspace_id, job, record, report, rows, batch, settings)
        return {
            "run_id": record["id"],
            "log_run_id": log.run_id if log else None,
            "ranked": len(report.ranked),
            "closed": len(report.closed),
            "needs_human": len(report.needs_human),
            "reused": len(report.reused),
            "case_state_rows": rows,
            "batch": batch.summary,
        }
    except Exception as exc:
        record["status"] = "FAILED"
        record["stage"] = "FAILED"
        record["finished"] = time.time()
        record["error"] = settings.redact(str(exc))[:500]
        if log is not None and log.run_id:
            try:
                log.transition(log.status(), "FAILED")
            except Exception:
                log.set_status("FAILED")
        queue.note(workspace_id, "triage_failed", f"Triage failed: {record['error']}", job_id=job["job_id"], run_id=record["id"], settings=settings)
        raise
    finally:
        engines.save_run(record)


def _needs_ingest(workspace_id: str, settings: Settings) -> bool:
    """Re-read advisories unless a refresh happened after the last sync and the last demo reset, recently."""
    from datetime import datetime

    refreshed = queue.last_fired(f"feed:{workspace_id}", settings)
    if refreshed is None or queue.now() - refreshed > FRESH_FEEDS:
        return True
    reset = queue.last_fired(EVIDENCE_RESET, settings)
    if reset is not None and reset >= refreshed:
        return True
    syncs = store.list_syncs(workspace_id=workspace_id, limit=1, settings=settings)
    finished = syncs[0].get("finished_at") if syncs else None
    return bool(finished and datetime.fromisoformat(str(finished)) > refreshed)


def _note_triage(workspace_id: str, job: dict[str, Any], record: dict[str, Any], report: Any, rows: int, batch: Any, settings: Settings) -> None:
    scope = "all services" if record.get("services") is None else ", ".join(record["services"])
    queue.note(
        workspace_id,
        "triage",
        f"Triage of {scope}: {len(report.ranked)} affected, {len(report.needs_human)} need a person, "
        f"{len(report.closed)} closed, {len(report.reused)} reused",
        detail={"reused": len(report.reused), "case_state_rows": rows, "batch": batch.summary, "trigger": job["trigger"]},
        job_id=job["job_id"],
        run_id=record["id"],
        settings=settings,
    )
    if report.needs_human:
        queue.note(
            workspace_id,
            "needs_human",
            f"{len(report.needs_human)} cases need a person's answer",
            detail={"cases": [card.case_id for card in report.needs_human[:20]]},
            job_id=job["job_id"],
            run_id=record["id"],
            settings=settings,
        )


class RationaleBatch:
    """Model rationales through one Nightshift batch job, recorded on the run log.

    What did not come back (a quiet window that did not open in time, a
    failed job, an answer that did not parse) goes through chat completions.
    """

    def __init__(self, settings: Settings, log: RunLog, receipts: list[dict[str, Any]], *, window: str) -> None:
        self.settings = settings
        self.log = log
        self.receipts = receipts
        self.window = window
        self.summary: dict[str, Any] = {}

    def __call__(self, requests: list[list[dict[str, str]]]) -> list[Any]:
        from sibyl.agents.prioritiser import Rationale
        from sibyl.llm.batch import NightshiftBatch

        runner = NightshiftBatch(self.settings, wait_seconds=120 if self.window == "quiet" else 180)
        try:
            result = runner.run(requests, Rationale, window=self.window)
        finally:
            runner.close()
        remember_calls(self.receipts, result.receipts, Rationale, self.log)
        self.summary = result.summary()
        self.summary["fallback"] = len(requests) - self.summary["answered"]
        self.log.event("prioritiser", "batch_job", self.summary)
        return result.outputs


# Memory curation --------------------------------------------------------------


def memory_curate(job: dict[str, Any], engines: Engines, settings: Settings) -> dict[str, Any]:
    from sibyl.orchestrator.casefile import service_of

    payload = job["payload"] or {}
    workspace_id = job["workspace_id"]
    workspace = store.get_workspace(workspace_id, settings)
    log = _job_log(job, settings, case_id=payload.get("case_id"), question_id=payload.get("question_id"))
    log.transition("PLANNED", "CURATING")
    hmem = engines.hmem_for(workspace_id)
    proposals = curate(hmem, engines.world_for(workspace_id), log)
    for proposal in proposals:
        queue.note(
            workspace_id,
            "approval",
            f"Memory proposes {proposal['source']} trust {proposal['previous']} → {proposal['weight']} for {proposal['ecosystem']}: {proposal['reason']}",
            detail=proposal,
            job_id=job["job_id"],
            run_id=log.run_id,
            settings=settings,
        )
    service_id = str(payload.get("service_id") or "") or service_of(str(payload.get("case_id") or ""))
    follow = None
    if service_id and not workspace["is_demo"]:
        try:
            service = store.get_service(service_id, settings)
        except store.NotFound:
            service = None
        if service is not None and (service.get("triage_policy") or "interval") != "manual":
            follow, _created = queue.enqueue(
                workspace_id,
                "triage",
                trigger="answer",
                payload={"services": [service_id], "incremental": True, "reason": "a person answered", "window": "now"},
                settings=settings,
            )
    log.decision("memory", "curated", proposals=len(proposals), triage=(follow or {}).get("job_id"))
    log.transition("CURATING", "DONE")
    return {"proposals": proposals, "triage": (follow or {}).get("job_id"), "log_run_id": log.run_id}


def curate(hmem: Any, world: Any, log: RunLog | None = None, *, threshold: int = 2) -> list[dict[str, Any]]:
    """Turn repeated human disagreement with one source into a pending trust proposal.

    Each stored resolution is compared with the source positions on the
    case's card. When people overruled the same source in the same
    ecosystem `threshold` times or more, and no proposal for it is pending,
    a lower weight is proposed. A person approves or rejects it in the inbox;
    nothing changes until then.
    """
    snapshot = hmem.snapshot()
    pending = {(item.get("source"), item.get("ecosystem")) for item in snapshot.get("pending") or [] if item.get("kind") == "trust"}
    against: Counter[tuple[str, str]] = Counter()
    examples: dict[tuple[str, str], list[str]] = {}
    for resolution in snapshot.get("resolutions") or []:
        decision = str(resolution.get("decision") or "")
        human = "not_affected" if decision == "accept_risk" else decision
        if human not in {"affected", "not_affected"}:
            continue
        case_id = str(resolution.get("case_id") or "")
        projection = world.case(case_id)
        placement = projection.get("placement") or projection.get("prior") or {}
        card = placement.get("card") if isinstance(placement, dict) else None
        if not isinstance(card, dict):
            continue
        ecosystem = str(card.get("ecosystem") or "*").lower() or "*"
        for position in card.get("positions") or []:
            source = str(position.get("source") or "")
            if source in {"", "human"} or position.get("verdict") not in {"affected", "not_affected"}:
                continue
            if position.get("verdict") != human:
                against[(source, ecosystem)] += 1
                examples.setdefault((source, ecosystem), []).append(case_id)
    proposals = []
    for (source, ecosystem), count in sorted(against.items()):
        if count < threshold or (source, ecosystem) in pending:
            continue
        current = hmem.trust(source, "affected_ranges", ecosystem) or 0.5
        weight = round(max(0.3, current - 0.1), 3)
        if weight >= current:
            continue
        reason = f"{count} human answers disagreed with {source} for {ecosystem}"
        queued = hmem.resolve(
            {
                "case_id": examples[(source, ecosystem)][0],
                "decision": "adjust_trust",
                "scope": "adjust_trust",
                "source": source,
                "field": "affected_ranges",
                "ecosystem": ecosystem,
                "weight": weight,
                "note": reason,
                "user": "memory_curate",
            }
        )
        if queued.get("pending"):
            proposals.append({"source": source, "ecosystem": ecosystem, "previous": current, "weight": weight, "reason": reason, "cases": examples[(source, ecosystem)][:5]})
    if log is not None and log.run_id:
        log.event("memory", "curation", {"disagreements": {f"{s}/{e}": n for (s, e), n in against.items()}, "proposals": len(proposals)})
    return proposals
