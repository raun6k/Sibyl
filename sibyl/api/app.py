"""Sibyl HTTP API.

Routes call the orchestrator, the agents, and H-MEM. They do not score cases.
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
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from sibyl.agents.scout import classify
from sibyl.config import ROOT, load_settings
from sibyl.engines.hmem import HmemClient
from sibyl.engines.world_model import WorldModelClient
from sibyl.llm.client import LLMClient, LLMUnavailable
from sibyl.orchestrator.log import RunLog
from sibyl.orchestrator.memory import resolve_case
from sibyl.orchestrator.run import run_triage
from sibyl.tools.zetaris import SqlRejected, run_sql, tracing_sql

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

DATASETS = {
    "fixtures": ROOT / "tests" / "fixtures" / "snapshots",
    "subset": ROOT / "data" / "sample" / "snapshot-subset",
    "full": ROOT / "data" / "sample" / "snapshots",
}
_SAFE = re.compile(r"^[A-Za-z0-9_.:@/-]+$")


class RunBody(BaseModel):
    dataset: str = "subset"
    disable_sources: list[str] = Field(default_factory=list)
    window_days: int = 14


class ResolveBody(BaseModel):
    decision: str
    note: str = ""
    user: str = ""
    remember: bool = True
    scope: str = "this_case"


class AskBody(BaseModel):
    question: str


class Hub:
    def __init__(self) -> None:
        self.hmem = HmemClient()
        self.world = WorldModelClient()
        self.runs: dict[str, dict[str, Any]] = {}
        self.order: list[str] = []
        self.current: str | None = None
        self.lock = threading.Lock()

    def close(self) -> None:
        self.hmem.close()
        self.world.close()


hub: Hub | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global hub
    hub = Hub()
    app.state.hub = hub
    yield
    hub.close()
    hub = None


app = FastAPI(title="Sibyl", lifespan=lifespan)


def _hub() -> Hub:
    if hub is None:
        raise HTTPException(status_code=503, detail="API is starting")
    return hub


@app.post("/runs", status_code=202)
def start_run(body: RunBody) -> dict[str, str]:
    active = _hub()
    if body.dataset not in DATASETS:
        raise HTTPException(status_code=422, detail="dataset must be fixtures, subset, or full")
    with active.lock:
        if active.current is not None:
            raise HTTPException(status_code=409, detail="a run is already in progress")
        run_id = str(uuid.uuid4())
        active.current = run_id
        record: dict[str, Any] = {
            "id": run_id,
            "status": "RUNNING",
            "stage": "PLANNED",
            "dataset": body.dataset,
            "window_days": body.window_days,
            "disable_sources": body.disable_sources,
            "started": time.time(),
            "report": None,
            "error": "",
            "log": None,
            "degraded_sources": list(body.disable_sources),
        }
        active.runs[run_id] = record
        active.order.append(run_id)
    threading.Thread(target=_execute, args=(record, body), daemon=True).start()
    return {"run_id": run_id}


@app.get("/runs")
def list_runs() -> dict[str, Any]:
    active = _hub()
    return {"runs": [_public(active.runs[run_id]) for run_id in reversed(active.order)]}


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
    report = _record(run_id).get("report")
    if not isinstance(report, dict):
        raise HTTPException(status_code=404, detail="the report is not ready")
    return report


@app.get("/cases/{case_id:path}")
def get_case(case_id: str) -> dict[str, Any]:
    card, record = _find_case(case_id)
    events: list[dict[str, Any]] = []
    log = record.get("log")
    if isinstance(log, RunLog):
        events = [event for event in log.feed() if (event.get("payload") or {}).get("case_id") == case_id]
    return {"case": card, "run_id": record["id"], "events": events, "provenance": _provenance(card)}


@app.get("/needs-human")
def needs_human() -> dict[str, Any]:
    report = _latest_report()
    return {"run_id": report.get("run_id"), "needs_human": report.get("needs_human") or []}


@app.post("/cases/{case_id:path}/resolution")
def post_resolution(case_id: str, body: ResolveBody) -> dict[str, Any]:
    card, _record = _find_case(case_id)
    return resolve_case(
        _hub().hmem,
        case_id=case_id,
        decision=body.decision,
        note=body.note,
        user=body.user,
        remember=body.remember,
        scope=body.scope,
        method=str(card.get("method") or ""),
        ecosystem="*",
        package=str(card.get("package") or ""),
        vuln_id=str(card.get("vuln_id") or ""),
    )


@app.get("/memory")
def get_memory() -> dict[str, Any]:
    try:
        return _hub().hmem.snapshot()
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
def approve_pending(pending_id: str) -> dict[str, Any]:
    return _hub().hmem.approve(pending_id)


@app.post("/memory/pending/{pending_id}/reject")
def reject_pending(pending_id: str) -> dict[str, Any]:
    return _hub().hmem.reject(pending_id)


@app.get("/inventory")
def inventory() -> dict[str, Any]:
    services = _query(
        "SELECT service_id, name, team, internet_facing, criticality, data_class FROM acme_internal.services ORDER BY service_id"
    )
    sboms = _query("SELECT sbom_id, service_id, generated_at, format FROM acme_internal.sboms")
    components = _query("SELECT sbom_id, ecosystem FROM acme_internal.components")
    by_service: dict[str, dict[str, int]] = {}
    sbom_of = {row["sbom_id"]: row for row in sboms}
    for row in components:
        sbom = sbom_of.get(row["sbom_id"])
        if not sbom:
            continue
        bucket = by_service.setdefault(sbom["service_id"], {"components": 0, "pypi": 0, "npm": 0})
        bucket["components"] += 1
        eco = (row.get("ecosystem") or "").lower()
        if eco in bucket:
            bucket[eco] += 1
    latest = _latest_report_or_none()
    counts = _service_counts(latest)
    cards = []
    for service in services:
        stats = by_service.get(service["service_id"], {"components": 0, "pypi": 0, "npm": 0})
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
    sample = load_settings().sample_mode
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
    active = _hub()
    with active.lock:
        if active.current is not None:
            raise HTTPException(status_code=409, detail="a run is already in progress")
        token = str(uuid.uuid4())
        active.current = token
    try:
        settings = load_settings()
        from run_demo import _bundles

        log = RunLog(settings)
        log.start({"kind": "point_question"}, {"max_tokens": settings.run_max_tokens, "max_seconds": settings.run_max_seconds})
        with LLMClient(settings) as client:
            speaker = _LoggingLLM(client, log)
            plan = classify(body.question, llm=speaker)
            cases = _bundles(
                settings,
                speaker,
                sorted(settings.disabled_sources()),
                plan.cve_id if plan.intent == "point_question" else None,
                active.hmem,
            )
            report = run_triage(cases, settings=settings, llm=speaker, log=log, hmem=active.hmem, world=active.world)
        cards = list(report.ranked) + list(report.needs_human) + list(report.closed)
        card = next((item for item in cards if plan.cve_id and plan.cve_id in item.case_id), cards[0] if cards else None)
        return {
            "question": body.question,
            "intent": plan.intent,
            "cve_id": plan.cve_id,
            "run_id": report.run_id,
            "case": card.model_dump() if card is not None else None,
        }
    finally:
        with active.lock:
            if active.current == token:
                active.current = None


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


def _execute(record: dict[str, Any], body: RunBody) -> None:
    active = _hub()
    settings = load_settings().model_copy(
        update={
            "sample_mode": True,
            "snapshot_dir": str(DATASETS[body.dataset]),
            "disable_sources": ",".join(body.disable_sources),
        }
    )
    log: RunLog | None = None
    try:
        from run_demo import _bundles, _prepare

        _prepare(settings)
        log = RunLog(settings)
        log.start(
            {
                "kind": "triage",
                "dataset": body.dataset,
                "window_days": body.window_days,
                "disable_sources": body.disable_sources,
            },
            {"max_tokens": settings.run_max_tokens, "max_seconds": settings.run_max_seconds},
        )
        record["log"] = log
        with LLMClient(settings) as client:
            speaker = _LoggingLLM(client, log)
            receipts: list[dict[str, Any]] = []
            with tracing_sql(log, receipts):
                cases = _bundles(settings, speaker, sorted(settings.disabled_sources()), None, active.hmem)
            report = run_triage(cases, settings=settings, llm=speaker, log=log, hmem=active.hmem, world=active.world)
        report.receipts["zetaris"] = receipts
        report.receipts["llm"] = speaker.receipts
        record["report"] = json.loads(report.model_dump_json())
        record["status"] = report.state
        record["stage"] = report.state
    except Exception as exc:
        record["status"] = "FAILED"
        record["stage"] = "FAILED"
        record["error"] = str(exc)
        if log is not None and log.run_id:
            try:
                log.transition(log.status(), "FAILED")
            except Exception:
                log.set_status("FAILED")
    finally:
        with active.lock:
            if active.current == record["id"]:
                active.current = None


def _stream(record: dict[str, Any], last: str | None) -> Iterator[str]:
    sent: set[str] = set()
    deadline = time.time() + load_settings().run_max_seconds + 120
    while time.time() < deadline:
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
            if not sent:
                yield f"id: end\ndata: {json.dumps({'type': 'state', 'actor': 'orchestrator', 'payload': {'to': record['status']}})}\n\n"
            return
        time.sleep(0.25)
    yield f"id: timeout\ndata: {json.dumps({'type': 'state', 'actor': 'orchestrator', 'payload': {'to': 'FAILED'}})}\n\n"


def _record(run_id: str) -> dict[str, Any]:
    found = _hub().runs.get(run_id)
    if found is None:
        raise HTTPException(status_code=404, detail="unknown run")
    return found


def _public(record: dict[str, Any]) -> dict[str, Any]:
    report = record.get("report") if isinstance(record.get("report"), dict) else {}
    elapsed = round(time.time() - float(record.get("started") or time.time()), 1)
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
        "status": record["status"],
        "stage": record.get("stage") or record["status"],
        "dataset": record.get("dataset"),
        "window_days": record.get("window_days"),
        "started": record.get("started"),
        "elapsed_seconds": elapsed,
        "counts": {
            "ranked": len(report.get("ranked") or []),
            "closed": len(report.get("closed") or []),
            "needs_human": len(report.get("needs_human") or []),
        },
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


def _latest_report() -> dict[str, Any]:
    report = _latest_report_or_none()
    if report is None:
        raise HTTPException(status_code=404, detail="no report yet")
    return report


def _latest_report_or_none() -> dict[str, Any] | None:
    active = _hub()
    for run_id in reversed(active.order):
        report = active.runs[run_id].get("report")
        if isinstance(report, dict):
            return report
    return None


def _find_case(case_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    active = _hub()
    for run_id in reversed(active.order):
        record = active.runs[run_id]
        report = record.get("report")
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


class _LoggingLLM:
    """Writes each Nightshift receipt onto the run log as it happens."""

    def __init__(self, inner: LLMClient, log: RunLog) -> None:
        self.inner = inner
        self.log = log
        self.receipts: list[dict[str, Any]] = []

    def complete(self, lane: str, messages: list[dict[str, str]], schema: type[Any]) -> Any:
        try:
            done = self.inner.complete(lane, messages, schema)
        except LLMUnavailable as exc:
            for receipt in exc.receipts:
                self._keep(receipt, schema)
            raise
        self._keep(done.receipt, schema)
        return done

    def _keep(self, receipt: Any, schema: type[Any]) -> None:
        agent = {
            "ExtractedRange": "matcher",
            "QuoteJudgement": "critic",
            "Rationale": "prioritiser",
            "IntentGuess": "scout",
            "ProductMatch": "mapper",
        }.get(getattr(schema, "__name__", ""), "model")
        self.receipts.append({**receipt.model_dump(), "agent": agent})
        if self.log.run_id:
            self.log.llm_call(agent, receipt)

