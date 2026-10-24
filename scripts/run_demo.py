#!/usr/bin/env python3
"""Headless Sibyl run on the frozen fixtures or a snapshot directory.

Resets evidence, seeds Acme, ingests, then runs the request through Scout
and the triage loop. Writes report.md, report.json, and trace.jsonl.

    uv run scripts/run_demo.py --label fixtures
    DISABLE_SOURCES=osv uv run scripts/run_demo.py --label fixtures-degraded
    uv run scripts/run_demo.py --label point-cve-2023-4863 --request "Are we affected by CVE-2023-4863?"
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from seed_db import evidence_counts, format_evidence_counts, main as seed_main, reset_evidence  # noqa: E402

from sibyl.agents.mapper import (  # noqa: E402
    english_description,
    find_text_cases,
    osv_listed,
    osv_not_listed,
)
from sibyl.agents.matcher import case_id_for, evaluate, load_candidates
from sibyl.agents.reporter import to_markdown
from sibyl.agents.scout import classify
from sibyl.config import load_settings
from sibyl.llm.client import LLMClient, LLMUnavailable
from sibyl.orchestrator.log import RunLog
from sibyl.orchestrator.run import Bundle, Clock, run_triage
from sibyl.tools.collectors import ingest


_AGENTS = {
    "ExtractedRange": "matcher",
    "QuoteJudgement": "critic",
    "Rationale": "prioritiser",
    "IntentGuess": "scout",
    "ProductMatch": "mapper",
}


class RecordingLLM:
    """Forwards to Nightshift and keeps every receipt, including a failed attempt."""

    def __init__(self, inner: LLMClient):
        self.inner = inner
        self.receipts: list[dict] = []

    def complete(self, lane, messages, schema):
        try:
            done = self.inner.complete(lane, messages, schema)
        except LLMUnavailable as exc:
            self._keep(exc.receipts, schema)
            raise
        self._keep(done.attempts, schema)
        self._keep((done.receipt,), schema)
        return done

    def _keep(self, receipts, schema) -> None:
        agent = _AGENTS.get(getattr(schema, "__name__", ""), "unknown")
        for receipt in receipts:
            payload = receipt.model_dump()
            payload["agent"] = agent
            self.receipts.append(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a headless Sibyl triage.")
    parser.add_argument("--label", required=True)
    parser.add_argument("--request", default="weekly triage over all services")
    parser.add_argument("--snapshot-dir", default=str(ROOT / "tests" / "fixtures" / "snapshots"))
    args = parser.parse_args(argv)
    started = time.perf_counter()
    settings = load_settings().model_copy(
        update={"sample_mode": True, "snapshot_dir": args.snapshot_dir}
    )
    if args.label == "fixtures-degraded" and "osv" not in settings.disabled_sources():
        settings = settings.model_copy(update={"disable_sources": "osv"})
    _prepare(settings)
    disabled = sorted(settings.disabled_sources())
    with LLMClient(settings) as client:
        recorder = RecordingLLM(client)
        plan = classify(args.request, llm=recorder)
        print(f"intent {plan.intent} cve {plan.cve_id} by {plan.classified_by}")
        timer = Clock()
        cases = _bundles(settings, recorder, disabled, plan.cve_id if plan.intent == "point_question" else None)
        log = RunLog(settings)
        report = run_triage(cases, settings=settings, llm=recorder, log=log, clock=timer)
        events = log.events()
    report.receipts["llm"] = recorder.receipts
    wall = round(time.perf_counter() - started, 1)
    out = ROOT / "output_examples" / args.label
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    (out / "report.md").write_text(to_markdown(report) + _llm_markdown(_llm_stats(recorder.receipts)), encoding="utf-8")
    with (out / "trace.jsonl").open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    summary = _summary(report, events, recorder.receipts, wall)
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"wrote {out.relative_to(ROOT)}")
    return 0 if report.state == "DONE" and not report.partial else 1


def _prepare(settings) -> None:
    import psycopg

    code = seed_main(["--reset-evidence"])
    if code != 0:
        raise SystemExit(code)
    with psycopg.connect(settings.database_url) as conn:
        before, sources = evidence_counts(conn)
        print(format_evidence_counts("evidence before ingest", before, sources))
    for item in ingest(settings=settings):
        print(item.summary())
        for error in item.errors:
            print(f"  {error}")
    with psycopg.connect(settings.database_url) as conn:
        after, sources = evidence_counts(conn)
        print(format_evidence_counts("evidence after ingest", after, sources))


def _bundles(settings, llm, disabled: list[str], only_cve: str | None) -> list[Bundle]:
    loaded = load_candidates(settings)
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in loaded.rows:
        grouped[case_id_for(row)].append(row)
    observations = find_text_cases(settings)
    if only_cve:
        grouped = {key: rows for key, rows in grouped.items() if only_cve in key}
        observations = [case for case in observations if case.vuln_id == only_cve]
    evaluated = evaluate(loaded.rows, observations, llm=llm)
    drafts = {
        verdict.case_id: verdict
        for verdict in evaluated.result.verdicts
        if verdict.method in {"text_llm", "quarantine"}
    }
    listed = osv_listed(settings)
    aliases = _aliases(settings)
    descriptions = _nvd_text(settings)
    siblings = _affected_siblings(grouped)
    bundles: list[Bundle] = []
    ids = list(grouped)
    for case in observations:
        if case.case_id not in grouped:
            ids.append(case.case_id)
    for case_id in ids:
        rows = grouped.get(case_id, [])
        draft = drafts.get(case_id)
        observation = next((item for item in observations if item.case_id == case_id), None)
        head = rows[0] if rows else {}
        package = (observation.package if observation else "") or str(head.get("package") or "")
        version = (observation.version if observation else "") or str(head.get("version") or "")
        vuln = (observation.vuln_id if observation else "") or str(head.get("cve_id") or head.get("vuln_id") or "")
        purl = str(head.get("purl") or (observation and f"pkg:{observation.ecosystem}/{observation.package}@{observation.version}") or "")
        service = str(head.get("service_id") or (observation.service_id if observation else ""))
        related = None
        if draft is not None and draft.verdict == "not_affected":
            others = [name for name in siblings.get((service, vuln), []) if name != package]
            related = others[0] if others else None
        bundles.append(
            Bundle(
                case_id=case_id,
                rows=[dict(row) for row in rows],
                package=package,
                version=version,
                vuln_id=vuln,
                ecosystem=str(head.get("ecosystem") or (observation.ecosystem if observation else "")),
                description=(observation.text if observation else "") or descriptions.get(vuln, ""),
                quote=evaluated.quotes.get(case_id, ""),
                applies_to_package=evaluated.applies.get(case_id),
                method=draft.method if draft is not None else "",
                verdict=draft.verdict if draft is not None else "",
                record_id=observation.record_id if observation else "",
                related_affected=related,
                disabled=disabled,
                osv_not_listed=osv_not_listed(purl, vuln, listed, aliases) if purl and vuln else False,
                internet_facing=str(head.get("internet_facing") or "").lower() in {"true", "t", "1"},
                criticality=float(head.get("criticality") or 0),
                exploited=bool(head.get("kev_date_added")),
                epss_percentile=float(head.get("epss_percentile") or 0),
                cvss=_cvss(head),
            )
        )
    return bundles


def _affected_siblings(grouped: dict[str, list[dict[str, str]]]) -> dict[tuple[str, str], list[str]]:
    """Packages that already have structured rows for a service and CVE."""
    found: dict[tuple[str, str], list[str]] = {}
    for rows in grouped.values():
        if not rows:
            continue
        head = rows[0]
        service = str(head.get("service_id") or "")
        vuln = str(head.get("cve_id") or head.get("vuln_id") or "")
        package = str(head.get("package") or "")
        if service and vuln and package and package not in found.setdefault((service, vuln), []):
            found[(service, vuln)].append(package)
    return found


def _aliases(settings) -> list[dict[str, str]]:
    import psycopg

    with psycopg.connect(settings.database_url) as conn:
        return [
            {"vuln_id": vuln, "alias_id": alias, "source": source}
            for vuln, alias, source in conn.execute(
                "SELECT vuln_id, alias_id, source FROM evidence.vuln_aliases"
            )
        ]


def _nvd_text(settings) -> dict[str, str]:
    import psycopg

    found: dict[str, str] = {}
    with psycopg.connect(settings.database_url) as conn:
        for source_id, raw in conn.execute(
            "SELECT source_id, raw_json FROM evidence.source_records WHERE source = 'nvd'"
        ):
            text = english_description("nvd", json.dumps(raw))
            if text:
                found[source_id] = text
    return found


def _cvss(row: dict) -> float:
    try:
        return float(row.get("cvss") or 0)
    except (TypeError, ValueError):
        return 0.0


def _summary(report, events, receipts, wall: float) -> dict:
    branches = {
        "ranked": len(report.ranked),
        "closed": len(report.closed),
        "needs_human": len(report.needs_human),
    }
    by_check: dict[str, set[str]] = {}
    cpe_cases: set[str] = set()
    escalated: set[str] = set()
    for event in events:
        payload = event.get("payload") or {}
        case_id = str(payload.get("case_id") or "")
        if event.get("type") == "decision" and payload.get("action") == "recheck":
            check = str(payload.get("check") or "recheck")
            by_check.setdefault(check, set()).add(case_id)
            if "contradicts" in str(payload.get("reason") or "").lower():
                cpe_cases.add(case_id)
        if event.get("type") == "escalation" and case_id:
            escalated.add(case_id)
    stats = _llm_stats(receipts)
    reroutes = [
        {
            "agent": item.get("agent"),
            "lane": item.get("lane"),
            "requested_model": item.get("requested_model"),
            "routed_model": item.get("routed_model"),
            "rerouted": item.get("rerouted"),
            "tokens": item.get("tokens"),
            "reasoning_tokens": item.get("reasoning_tokens"),
            "latency_ms": item.get("latency_ms"),
            "error_code": item.get("error_code") or "",
        }
        for item in receipts
    ]
    return {
        "state": report.state,
        "partial": report.partial,
        "degraded": report.degraded,
        "wall_seconds": wall,
        "tokens": stats["tokens"],
        "llm_calls": stats["calls"],
        "llm": stats,
        "branches": branches,
        "sendbacks": {check: len(cases) for check, cases in sorted(by_check.items())},
        "cpe_sendbacks": len(cpe_cases),
        "cpe_escalations": len(cpe_cases & escalated),
        "escalations": len(escalated),
        "receipts": reroutes,
    }


def _llm_stats(receipts: list[dict]) -> dict:
    grouped: dict[str, dict[str, int]] = {}
    latencies: list[float] = []
    tokens = 0
    for item in receipts:
        agent = str(item.get("agent") or "unknown")
        lane = str(item.get("lane") or "unknown")
        grouped.setdefault(agent, {})
        grouped[agent][lane] = grouped[agent].get(lane, 0) + 1
        latencies.append(float(item.get("latency_ms") or 0))
        tokens += int(item.get("tokens") or 0)
    return {
        "calls_by_agent_lane": grouped,
        "calls": len(receipts),
        "latency_ms_total": round(sum(latencies), 1),
        "latency_ms_p95": _p95(latencies),
        "tokens": tokens,
    }


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return round(ordered[index], 1)


def _llm_markdown(stats: dict) -> str:
    lines = ["", "## LLM", ""]
    calls = stats.get("calls_by_agent_lane") or {}
    if not calls:
        lines.append("No model calls.")
    for agent, lanes in calls.items():
        for lane, count in lanes.items():
            lines.append(f"- {agent} {lane}: {count}")
    lines.append(
        f"Latency total {stats.get('latency_ms_total')} ms, "
        f"p95 {stats.get('latency_ms_p95')} ms, tokens {stats.get('tokens')}."
    )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
