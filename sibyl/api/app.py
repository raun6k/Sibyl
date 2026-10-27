"""Sibyl HTTP API.

Routes call the orchestrator, the agents, and H-MEM. They do not score cases.
Every run, report, queue and memory belongs to one workspace. The demo
workspace runs on the sample snapshots; any other workspace runs live on
the advisories for its own packages. Workspace, repository, service and
question routes are in `sibyl.api.workspaces`.

A run is a `triage` job on the queue (`sibyl.jobs`); "a run is already in
progress" no longer exists. Each workspace has a persistent World Model
(its event log in `world.events`), and a run's report is that World Model's
`report` view: `var/runs/*.json` keeps run metadata only.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from sibyl.agents.reporter import Report, to_markdown
from sibyl.api.review_queue import unresolved_cases
from sibyl.agents.scout import classify
from sibyl.config import ROOT, load_settings
from sibyl.engines.hmem import STORE as HMEM_STORE
from sibyl.engines.hmem import HmemClient
from sibyl.engines.world_model import WorldModelClient
from sibyl.inventory import store
from sibyl.inventory.schema import DEMO_WORKSPACE
from sibyl.jobs import queue
from sibyl.jobs.handlers import DATASETS
from sibyl.jobs.locks import LockTimeout, evidence_lock
from sibyl.llm.client import LLMClient
from sibyl.orchestrator.log import RunLog
from sibyl.orchestrator.memory import resolve_case
from sibyl.orchestrator.receipts import LoggingLLM
from sibyl.orchestrator.run import run_triage
from sibyl.tools.zetaris import SqlRejected, run_sql

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

_SAFE = re.compile(r"^[A-Za-z0-9_.:@/-]+$")
# Finished runs are saved here so a restart keeps the runs, their reports and their traces.
RUNS_DIR = ROOT / "var" / "runs"
# Run metadata only. The report is the World Model's view of the run (`log_run_id`).
_SAVED = (
    "id",
    "workspace_id",
    "status",
    "stage",
    "dataset",
    "window_days",
    "disable_sources",
    "started",
    "finished",
    "error",
    "degraded_sources",
    "job_id",
    "trigger",
    "services",
    "incremental",
    "reused",
    "counts",
)


class RunBody(BaseModel):
    workspace_id: str = DEMO_WORKSPACE
    # fixtures, subset or full for the demo workspace; live for any other workspace.
    dataset: str = "subset"
    disable_sources: list[str] = Field(default_factory=list)
    window_days: int = 14
    # Reuse verdicts whose claims and component did not change. False re-checks every case.
    incremental: bool = True
    # Only these services; None is the whole workspace.
    services: list[str] | None = None


class ResolveBody(BaseModel):
    decision: str
    note: str = ""
    user: str = ""
    remember: bool = True
    scope: str = "this_case"


class AskBody(BaseModel):
    question: str
    workspace_id: str = DEMO_WORKSPACE


class Hub:
    """Runs in memory, and one H-MEM and one World Model process per workspace, started on first use.

    The World Model of a workspace is persistent: it replays `world.events`
    on start. The scheduler and the workers run background jobs.
    """

    def __init__(self) -> None:
        self.runs: dict[str, dict[str, Any]] = {}
        self.order: list[str] = []
        self.lock = threading.Lock()
        self._hmem: dict[str, HmemClient] = {}
        self._world: dict[str, WorldModelClient] = {}
        self._engines = threading.Lock()
        self.scheduler: Any = None

    @property
    def hmem(self) -> HmemClient:
        return self.hmem_for(DEMO_WORKSPACE)

    @property
    def world(self) -> WorldModelClient:
        return self.world_for(DEMO_WORKSPACE)

    def hmem_for(self, workspace_id: str) -> HmemClient:
        with self._engines:
            client = self._hmem.get(workspace_id)
            if client is None:
                client = self._hmem[workspace_id] = HmemClient(hmem_dir(workspace_id))
            return client

    def world_for(self, workspace_id: str) -> WorldModelClient:
        with self._engines:
            client = self._world.get(workspace_id)
            if client is None:
                client = self._world[workspace_id] = WorldModelClient(namespace=workspace_id, persist=True)
            return client

    def new_run_record(self, workspace_id: str, **fields: Any) -> dict[str, Any]:
        run_id = str(uuid.uuid4())
        record: dict[str, Any] = {
            "id": run_id,
            "workspace_id": workspace_id,
            "status": "QUEUED",
            "stage": "QUEUED",
            "dataset": fields.get("dataset"),
            "window_days": fields.get("window_days", 14),
            "disable_sources": fields.get("disable_sources") or [],
            "started": time.time(),
            "report": None,
            "error": "",
            "log": None,
            "degraded_sources": list(fields.get("disable_sources") or []),
        }
        with self.lock:
            self.runs[run_id] = record
            self.order.append(run_id)
        return record

    def save_run(self, record: dict[str, Any]) -> None:
        try:
            save_run(record)
        except OSError:
            pass

    def wake(self) -> None:
        if self.scheduler is not None:
            self.scheduler.wake()

    def drop_workspace(self, workspace_id: str) -> None:
        with self._engines:
            for clients in (self._hmem, self._world):
                client = clients.pop(workspace_id, None)
                if client is not None:
                    client.close()

    def close(self) -> None:
        if self.scheduler is not None:
            self.scheduler.stop()
        with self._engines:
            for client in [*self._hmem.values(), *self._world.values()]:
                client.close()
            self._hmem.clear()
            self._world.clear()


def hmem_dir(workspace_id: str) -> Path:
    """The demo workspace keeps the original store; every other workspace gets its own."""
    if workspace_id == DEMO_WORKSPACE:
        return HMEM_STORE
    return HMEM_STORE / "workspaces" / workspace_id


hub: Hub | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global hub
    hub = Hub()
    try:
        store.ensure()
    except Exception as exc:  # the API still serves saved runs without Postgres
        print(f"inventory schema not checked: {exc}", file=sys.stderr)
    for record in load_runs(RUNS_DIR):
        hub.runs[record["id"]] = record
        hub.order.append(record["id"])
    app.state.hub = hub
    try:
        from sibyl.jobs.scheduler import Scheduler

        settings = load_settings()
        hub.scheduler = Scheduler(hub, settings, automatic=settings.scheduler_enabled)
        hub.scheduler.start()
    except Exception as exc:  # no Postgres: the API still serves saved runs
        print(f"scheduler not started: {exc}", file=sys.stderr)
    yield
    hub.close()
    hub = None


app = FastAPI(title="Sibyl", lifespan=lifespan)


def save_run(record: dict[str, Any], directory: Path = RUNS_DIR) -> None:
    """Write a finished run's metadata. The trace stays in evidence.run_events and the report in the World Model."""
    report = record.get("report") if isinstance(record.get("report"), dict) else None
    if report is not None:
        record["counts"] = {name: len(report.get(name) or []) for name in ("ranked", "closed", "needs_human")}
        record["reused"] = len(report.get("reused") or [])
    saved = {key: record.get(key) for key in _SAVED}
    log = record.get("log")
    saved["log_run_id"] = log.run_id if isinstance(log, RunLog) else record.get("log_run_id")
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{record['id']}.json"
    partial = target.with_suffix(".json.tmp")
    partial.write_text(json.dumps(saved), encoding="utf-8")
    partial.replace(target)


def load_runs(directory: Path = RUNS_DIR) -> list[dict[str, Any]]:
    """Saved runs, oldest first. A file that does not parse is skipped."""
    records: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            saved = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(saved, dict) or not saved.get("id") or saved.get("status") not in {"DONE", "FAILED"}:
            continue
        record = {key: saved.get(key) for key in _SAVED}
        # Runs saved before P10 kept the report in the file; later runs read it from the World Model.
        record["report"] = saved.get("report") if isinstance(saved.get("report"), dict) else None
        record["log_run_id"] = saved.get("log_run_id")
        record["workspace_id"] = record.get("workspace_id") or DEMO_WORKSPACE
        record["degraded_sources"] = record.get("degraded_sources") or []
        record["log"] = None
        if saved.get("log_run_id"):
            log = RunLog(load_settings())
            log.run_id = saved["log_run_id"]
            record["log"] = log
        records.append(record)
    return sorted(records, key=lambda item: float(item.get("started") or 0))


def _hub() -> Hub:
    if hub is None:
        raise HTTPException(status_code=503, detail="API is starting")
    return hub


@app.post("/runs", status_code=202)
def start_run(body: RunBody) -> dict[str, Any]:
    """Queue a triage. It starts when the workspace's earlier jobs are done."""
    active = _hub()
    workspace = _workspace(body.workspace_id)
    if workspace["is_demo"]:
        if body.dataset not in DATASETS:
            raise HTTPException(status_code=422, detail="dataset must be fixtures, subset, or full")
    else:
        body = body.model_copy(update={"dataset": "live"})
    if body.services is not None:
        known = {service["service_id"] for service in store.list_services(body.workspace_id)}
        unknown = [name for name in body.services if name not in known]
        if unknown or not body.services:
            raise HTTPException(status_code=422, detail="unknown services: " + ", ".join(unknown or ["(none named)"]))
    record = active.new_run_record(
        body.workspace_id,
        dataset=body.dataset,
        window_days=body.window_days,
        disable_sources=body.disable_sources,
    )
    job, _created = queue.enqueue(
        body.workspace_id,
        "triage",
        trigger="manual",
        payload={
            "record_id": record["id"],
            "dataset": body.dataset,
            "window_days": body.window_days,
            "disable_sources": body.disable_sources,
            "incremental": body.incremental,
            "services": body.services,
            "window": "now",
        },
        run_id=record["id"],
        merge=False,
    )
    record.update({"job_id": job["job_id"], "trigger": "manual", "services": body.services, "incremental": body.incremental})
    active.wake()
    return {"run_id": record["id"], "job_id": job["job_id"], "status": "QUEUED"}


@app.get("/runs")
def list_runs(workspace: str | None = None) -> dict[str, Any]:
    active = _hub()
    records = [active.runs[run_id] for run_id in reversed(active.order)]
    if workspace:
        records = [record for record in records if record.get("workspace_id", DEMO_WORKSPACE) == workspace]
    return {"runs": [_public(record) for record in records]}


@app.get("/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    return _public(_record(run_id))


@app.get("/runs/{run_id}/events")
def stream_events(run_id: str, request: Request) -> StreamingResponse:
    record = _record(run_id)
    last = request.headers.get("last-event-id")
    return StreamingResponse(_stream(record, last), media_type="text/event-stream")


@app.get("/runs/{run_id}/report")
def get_report(run_id: str) -> dict[str, Any]:
    """`report.json`: the World Model's report view of this run."""
    report = _report_of(_record(run_id))
    if report is None:
        raise HTTPException(status_code=404, detail="the report is not ready")
    return report


@app.get("/runs/{run_id}/report.md")
def get_report_markdown(run_id: str):
    """`report.md`: the same view as Markdown."""
    from fastapi.responses import PlainTextResponse

    report = _report_of(_record(run_id))
    if report is None:
        raise HTTPException(status_code=404, detail="the report is not ready")
    return PlainTextResponse(to_markdown(Report.model_validate(report)), media_type="text/markdown")


@app.get("/cases/{case_id:path}")
def get_case(case_id: str) -> dict[str, Any]:
    card, record = _find_case(case_id)
    events: list[dict[str, Any]] = []
    log = record.get("log")
    if isinstance(log, RunLog):
        events = [event for event in log.feed() if (event.get("payload") or {}).get("case_id") == case_id]
    return {"case": card, "run_id": record["id"], "events": events, "provenance": _provenance(card)}


@app.get("/current")
def current_report(workspace: str = DEMO_WORKSPACE) -> dict[str, Any]:
    """Every case as the World Model holds it now, across runs, in the report's shape."""
    current = current_cards(workspace)
    if current is None:
        return _latest_report(workspace)
    branches: dict[str, list[dict[str, Any]]] = {"ranked": [], "closed": [], "needs_human": []}
    for item in current:
        card = dict(item.get("card") or {})
        card["reused_from"] = item.get("reused_from")
        branches.get(str(item.get("placement")), branches["needs_human"]).append(card)
    branches["ranked"].sort(key=lambda card: float(card.get("score") or 0), reverse=True)
    latest = _latest_report_or_none(workspace) or {}
    return {
        "run_id": latest.get("run_id") or "",
        "state": "DONE",
        "partial": False,
        "degraded": bool(latest.get("degraded")),
        "unprocessed": [],
        **branches,
        "reused": [card["case_id"] for branch in branches.values() for card in branch if card.get("reused_from")],
        "receipts": {"zetaris": [], "llm": []},
        "current": True,
    }


@app.get("/needs-human")
def needs_human(workspace: str = DEMO_WORKSPACE) -> dict[str, Any]:
    """Cases that need a person now: the World Model's current case state, across runs."""
    current = current_cards(workspace)
    if current is None:
        report = _latest_report(workspace)
        cards = report.get("needs_human") or []
        return {"run_id": report.get("run_id"), "needs_human": unresolved_cases(cards, _hub().hmem_for(workspace))}
    cards = [item["card"] | {"run_id": item.get("run_id")} for item in current if item.get("placement") == "needs_human"]
    latest = _latest_report_or_none(workspace) or {}
    return {"run_id": latest.get("run_id"), "needs_human": unresolved_cases(cards, _hub().hmem_for(workspace))}


@app.post("/cases/{case_id:path}/resolution")
def post_resolution(case_id: str, body: ResolveBody) -> dict[str, Any]:
    card, record = _find_case(case_id)
    workspace_id = record.get("workspace_id") or DEMO_WORKSPACE
    resolved = resolve_case(
        _hub().hmem_for(workspace_id),
        case_id=case_id,
        decision=body.decision,
        note=body.note,
        user=body.user,
        remember=body.remember,
        scope=body.scope,
        method=str(card.get("method") or ""),
        ecosystem=_ecosystem(card),
        package=str(card.get("package") or ""),
        vuln_id=str(card.get("vuln_id") or ""),
    )
    if body.remember:
        queue.enqueue(workspace_id, "memory_curate", trigger="answer", payload={"case_id": case_id, "decision": body.decision})
        queue.note(workspace_id, "answer", f"You answered {case_id}: {body.decision}", detail={"scope": body.scope})
        _hub().wake()
    return resolved


@app.get("/memory")
def get_memory(workspace: str = DEMO_WORKSPACE) -> dict[str, Any]:
    try:
        return _hub().hmem_for(workspace).snapshot()
    except Exception as exc:
        return {
            "unavailable": True,
            "error": str(exc),
            "pending": [],
            "trust": [],
            "mappings": [],
            "resolutions": [],
        }


@app.post("/memory/pending/{pending_id}/approve")
def approve_pending(pending_id: str, workspace: str = DEMO_WORKSPACE) -> dict[str, Any]:
    return _hub().hmem_for(workspace).approve(pending_id)


@app.post("/memory/pending/{pending_id}/reject")
def reject_pending(pending_id: str, workspace: str = DEMO_WORKSPACE) -> dict[str, Any]:
    return _hub().hmem_for(workspace).reject(pending_id)


@app.get("/inventory")
def inventory(workspace: str = DEMO_WORKSPACE) -> dict[str, Any]:
    """The workspace's services and component counts, read through Zetaris."""
    if not store.safe_id(workspace):
        raise HTTPException(status_code=422, detail="unknown workspace")
    services = _query(
        "SELECT service_id, name, team, internet_facing, criticality, data_class, repo_id, path FROM inventory.services "
        f"WHERE workspace_id = '{workspace}' AND status = 'active' ORDER BY service_id"
    )
    ids = [row["service_id"] for row in services if _SAFE.fullmatch(row["service_id"])]
    sboms: list[dict[str, str]] = []
    components: list[dict[str, str]] = []
    if ids:
        quoted = ", ".join(f"'{item}'" for item in ids)
        sboms = _query(f"SELECT sbom_id, service_id, generated_at, format FROM inventory.sboms WHERE service_id IN ({quoted})")
        components = _query(
            "SELECT components.sbom_id, components.ecosystem FROM inventory.components AS components "
            f"JOIN inventory.sboms AS sboms ON components.sbom_id = sboms.sbom_id WHERE sboms.service_id IN ({quoted})"
        )
    by_service: dict[str, dict[str, Any]] = {}
    sbom_of = {row["sbom_id"]: row for row in sboms}
    for row in components:
        sbom = sbom_of.get(row["sbom_id"])
        if not sbom:
            continue
        bucket = by_service.setdefault(sbom["service_id"], {"components": 0, "pypi": 0, "npm": 0, "ecosystems": {}})
        bucket["components"] += 1
        eco = (row.get("ecosystem") or "").lower()
        if eco in {"pypi", "npm"}:
            bucket[eco] += 1
        bucket["ecosystems"][eco] = bucket["ecosystems"].get(eco, 0) + 1
    latest = _latest_report_or_none(workspace)
    current = current_cards(workspace)
    counts = _current_counts(current) if current is not None else _service_counts(latest)
    cards = []
    for service in services:
        stats = by_service.get(service["service_id"], {"components": 0, "pypi": 0, "npm": 0, "ecosystems": {}})
        extra = counts.get(service["service_id"], {"affected": 0, "needs_human": 0})
        generated = next((row.get("generated_at") for row in sboms if row["service_id"] == service["service_id"]), "")
        cards.append({**service, **stats, **extra, "sbom_at": generated})
    return {"services": cards, "components": len(components), "run_id": (latest or {}).get("run_id")}


@app.get("/sources")
def sources() -> dict[str, Any]:
    rows = _query("SELECT source FROM evidence.source_records")
    counts: dict[str, int] = {}
    for row in rows:
        name = row.get("source") or ""
        counts[name] = counts.get(name, 0) + 1
    latest = _latest_record()
    disabled = set((latest or {}).get("degraded_sources") or [])
    sample = load_settings().sample_mode and (latest or {}).get("dataset") != "live"
    health = [
        {
            "source": name,
            "records": count,
            "status": "degraded" if name in disabled else "snapshot" if sample else "live",
        }
        for name, count in sorted(counts.items())
    ]
    return {"sources": health, "run_id": (latest or {}).get("id")}


@app.post("/ask")
def ask(body: AskBody) -> dict[str, Any]:
    """A point question, answered now. It waits only while a demo run resets evidence."""
    active = _hub()
    workspace = _workspace(body.workspace_id)
    settings = load_settings().model_copy(update={"workspace_id": body.workspace_id})
    if not workspace["is_demo"]:
        settings = settings.model_copy(update={"sample_mode": False})
    from run_demo import _bundles

    try:
        with evidence_lock(exclusive=False, wait_seconds=5):
            log = RunLog(settings)
            log.start({"kind": "point_question"}, {"max_tokens": settings.run_max_tokens, "max_seconds": settings.run_max_seconds})
            with LLMClient(settings) as client:
                speaker = LoggingLLM(client, log)
                plan = classify(body.question, llm=speaker)
                log.transition("PLANNED", "COLLECTING")
                cases = _bundles(
                    settings,
                    speaker,
                    sorted(settings.disabled_sources()),
                    plan.cve_id if plan.intent == "point_question" else None,
                    active.hmem_for(body.workspace_id),
                    trace=log,
                )
                report = run_triage(
                    cases,
                    settings=settings,
                    llm=speaker,
                    log=log,
                    hmem=active.hmem_for(body.workspace_id),
                    world=active.world_for(body.workspace_id),
                    precollected=True,
                    covers=[],
                    receipts={"zetaris": [], "llm": speaker.receipts},
                )
    except LockTimeout:
        raise HTTPException(status_code=409, detail="a demo run is resetting evidence; ask again when it finishes") from None
    cards = list(report.ranked) + list(report.needs_human) + list(report.closed)
    card = next((item for item in cards if plan.cve_id and plan.cve_id in item.case_id), cards[0] if cards else None)
    return {
        "question": body.question,
        "intent": plan.intent,
        "cve_id": plan.cve_id,
        "run_id": report.run_id,
        "case": card.model_dump() if card is not None else None,
    }


@app.get("/baselines/{label}")
def baselines(label: str) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", label):
        raise HTTPException(status_code=422, detail="unknown label")
    path = ROOT / "eval" / "results" / f"baselines-{label}.jsonl"
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"no baselines for {label}")
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("baseline") == "B1":
            rows.append(item)
    return {"label": label, "baseline": "B1", "rows": rows}


def _workspace(workspace_id: str) -> dict[str, Any]:
    if not store.safe_id(workspace_id):
        raise HTTPException(status_code=404, detail="unknown workspace")
    try:
        return store.get_workspace(workspace_id)
    except store.NotFound:
        raise HTTPException(status_code=404, detail="unknown workspace") from None


def _stream(record: dict[str, Any], last: str | None) -> Iterator[str]:
    sent: set[str] = set()
    budget = load_settings().run_max_seconds + 120
    deadline = time.time() + budget
    while time.time() < deadline:
        if record.get("status") == "QUEUED":
            # Waiting in the queue does not use the run's time budget.
            deadline = time.time() + budget
            time.sleep(0.5)
            continue
        log = record.get("log")
        if isinstance(log, RunLog) and log.run_id:
            for event in log.feed(last):
                if event["event_id"] in sent:
                    continue
                payload = event.get("payload") or {}
                if event.get("type") == "state" and payload.get("to") == "DONE" and not isinstance(record.get("report"), dict):
                    break
                sent.add(event["event_id"])
                if event.get("type") == "state" and payload.get("to"):
                    record["stage"] = payload["to"]
                yield f"id: {event['event_id']}\ndata: {json.dumps(event)}\n\n"
                if event.get("type") == "state" and payload.get("to") in {"DONE", "FAILED"}:
                    return
        if record["status"] in {"DONE", "FAILED"}:
            yield f"event: end\ndata: {json.dumps({'status': record['status'], 'events': len(sent)})}\n\n"
            return
        time.sleep(0.25)
    yield f"event: trace_error\ndata: {json.dumps({'detail': 'The trace connection timed out; reconnect to continue.'})}\n\n"


def _record(run_id: str) -> dict[str, Any]:
    found = _hub().runs.get(run_id)
    if found is None:
        raise HTTPException(status_code=404, detail="unknown run")
    return found


def _public(record: dict[str, Any]) -> dict[str, Any]:
    report = record.get("report") if isinstance(record.get("report"), dict) else {}
    counts = record.get("counts") if not report and isinstance(record.get("counts"), dict) else None
    # A finished run keeps the time it took, not the time since it started.
    ended = float(record.get("finished") or time.time())
    elapsed = round(ended - float(record.get("started") or ended), 1)
    tokens = 0
    log = record.get("log")
    if isinstance(log, RunLog) and log.run_id:
        try:
            for event in log.feed():
                if event.get("type") == "llm_call":
                    tokens += int((event.get("payload") or {}).get("tokens") or 0)
                if event.get("type") == "state" and (event.get("payload") or {}).get("to"):
                    record["stage"] = (event.get("payload") or {})["to"]
        except Exception:
            pass
    settings = load_settings()
    return {
        "run_id": record["id"],
        "workspace_id": record.get("workspace_id") or DEMO_WORKSPACE,
        "status": record["status"],
        "stage": record.get("stage") or record["status"],
        "dataset": record.get("dataset"),
        "window_days": record.get("window_days"),
        "started": record.get("started"),
        "elapsed_seconds": elapsed,
        "counts": counts
        or {
            "ranked": len(report.get("ranked") or []),
            "closed": len(report.get("closed") or []),
            "needs_human": len(report.get("needs_human") or []),
        },
        "reused": len(report.get("reused") or []) if report else int(record.get("reused") or 0),
        "job_id": record.get("job_id"),
        "trigger": record.get("trigger") or "manual",
        "services": record.get("services"),
        "incremental": record.get("incremental", False),
        "budget": {
            "tokens": tokens,
            "max_tokens": settings.run_max_tokens,
            "seconds": elapsed,
            "max_seconds": settings.run_max_seconds,
        },
        "degraded_sources": record.get("degraded_sources") or [],
        "error": record.get("error") or "",
    }


def _latest_record() -> dict[str, Any] | None:
    active = _hub()
    for run_id in reversed(active.order):
        return active.runs[run_id]
    return None


def _latest_report(workspace: str = DEMO_WORKSPACE) -> dict[str, Any]:
    report = _latest_report_or_none(workspace)
    if report is None:
        raise HTTPException(status_code=404, detail="no report yet")
    return report


def _latest_report_or_none(workspace: str = DEMO_WORKSPACE) -> dict[str, Any] | None:
    active = _hub()
    for run_id in reversed(active.order):
        record = active.runs[run_id]
        if (record.get("workspace_id") or DEMO_WORKSPACE) != workspace:
            continue
        if record.get("status") not in {"DONE", None} and record.get("report") is None:
            continue
        report = _report_of(record)
        if isinstance(report, dict):
            return report
    return None


def _report_of(record: dict[str, Any]) -> dict[str, Any] | None:
    """The run's report: the World Model's view, kept in memory after the first read."""
    report = record.get("report")
    if isinstance(report, dict):
        return report
    log = record.get("log")
    log_run_id = log.run_id if isinstance(log, RunLog) else record.get("log_run_id")
    if not log_run_id or record.get("status") not in {"DONE", "FAILED"}:
        return None
    try:
        projected = _hub().world_for(record.get("workspace_id") or DEMO_WORKSPACE).report(str(log_run_id))
    except Exception:
        return None
    if isinstance(projected, dict):
        projected["run_id"] = projected.get("run_id") or log_run_id
        record["report"] = projected
    return projected


def current_cards(workspace: str) -> list[dict[str, Any]] | None:
    """The World Model's current case state for a workspace, or None before its first P10 run."""
    try:
        world = _hub().world_for(workspace)
        if not world.runs():
            return None
        return world.current_cases()
    except Exception:
        return None


def _current_counts(current: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for item in current:
        name = str(item.get("service_id") or "")
        bucket = counts.setdefault(name, {"affected": 0, "needs_human": 0})
        if item.get("placement") == "ranked" and (item.get("card") or {}).get("verdict") == "affected":
            bucket["affected"] += 1
        elif item.get("placement") == "needs_human":
            bucket["needs_human"] += 1
    return counts


def _find_case(case_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    active = _hub()
    for run_id in reversed(active.order):
        record = active.runs[run_id]
        report = _report_of(record)
        if not isinstance(report, dict):
            continue
        for branch in ("ranked", "closed", "needs_human"):
            for card in report.get(branch) or []:
                if card.get("case_id") == case_id:
                    return card, record
    raise HTTPException(status_code=404, detail="unknown case")


def _service_counts(report: dict[str, Any] | None) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    if not report:
        return counts
    for card in report.get("ranked") or []:
        if card.get("verdict") != "affected":
            continue
        name = _service_of(str(card.get("case_id") or ""))
        counts.setdefault(name, {"affected": 0, "needs_human": 0})["affected"] += 1
    for card in report.get("needs_human") or []:
        name = _service_of(str(card.get("case_id") or ""))
        counts.setdefault(name, {"affected": 0, "needs_human": 0})["needs_human"] += 1
    return counts


def _ecosystem(card: dict[str, Any]) -> str:
    """The purl type. A trust change is stored for that ecosystem only."""
    named = str(card.get("ecosystem") or "").strip().lower()
    if named and named != "*":
        return named
    match = re.search(r"pkg:([^/]+)/", str(card.get("purl") or card.get("case_id") or ""))
    if match:
        return match.group(1).lower()
    return "*"


def _service_of(case_id: str) -> str:
    parts = case_id.split(":")
    return parts[1] if len(parts) > 1 else ""


def _provenance(card: dict[str, Any]) -> dict[str, Any]:
    ids = [str(item) for item in card.get("record_ids") or [] if _SAFE.fullmatch(str(item))]
    if not ids:
        return {"records": [], "matrix": []}
    quoted = ", ".join(f"'{item}'" for item in ids)
    records = _query(
        "SELECT record_id, source, source_id, status, retrieved_at FROM evidence.source_records "
        f"WHERE record_id IN ({quoted})"
    )
    affected = _query(
        "SELECT record_id, vuln_id, package, fixed, last_affected FROM evidence.affected WHERE record_id IN ("
        + quoted
        + ")"
    )
    severities = _query(
        "SELECT record_id, source, score, version FROM evidence.severities WHERE record_id IN (" + quoted + ")"
    )
    sources = sorted({row.get("source") or "" for row in records if row.get("source")})
    matrix = []
    for field in ("affected_ranges", "fixed_version", "severity_cvss", "exploited", "aliases", "withdrawn"):
        matrix.append(
            {
                "field": field,
                "cells": {
                    source: _mark(field, source, records, affected, severities, card) for source in sources
                },
            }
        )
    return {"records": records, "affected": affected, "severities": severities, "matrix": matrix}


def _mark(
    field: str,
    source: str,
    records: list[dict[str, str]],
    affected: list[dict[str, str]],
    severities: list[dict[str, str]],
    card: dict[str, Any],
) -> str:
    owned = {row["record_id"] for row in records if row.get("source") == source}
    if field == "affected_ranges":
        return "star" if any(row["record_id"] in owned for row in affected) else "none"
    if field == "fixed_version":
        return "star" if any(row["record_id"] in owned and row.get("fixed") for row in affected) else "none"
    if field == "severity_cvss":
        return "star" if any(row.get("source") == source for row in severities) else "none"
    if field == "withdrawn":
        return "miss" if any(row["record_id"] in owned and row.get("status") in {"withdrawn", "rejected"} for row in records) else "none"
    if field == "exploited":
        return "star" if card.get("exploited") and source in {"kev", "euvd", "cisa-adp"} else "none"
    return "partial" if owned else "none"


def _query(sql: str) -> list[dict[str, str]]:
    try:
        loaded = run_sql(sql, limit=20000)
    except SqlRejected:
        raise
    if loaded.truncated:
        raise HTTPException(status_code=409, detail="the query reached its row limit")
    return loaded.rows




from sibyl.api.workspaces import router as workspace_router  # noqa: E402

app.include_router(workspace_router)
