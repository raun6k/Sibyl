#!/usr/bin/env python3
"""Headless Sibyl run on the frozen fixtures or a snapshot directory.

Resets evidence, seeds the demo workspace, ingests, then runs the request through Scout
and the triage loop. Writes report.md, report.json, and trace.jsonl.

    uv run scripts/run_demo.py --label fixtures
    DISABLE_SOURCES=osv uv run scripts/run_demo.py --label fixtures-degraded
    uv run scripts/run_demo.py --label point-cve-2023-4863 --request "Are we affected by CVE-2023-4863?"
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from seed_db import evidence_counts, format_evidence_counts, main as seed_main  # noqa: E402

from sibyl.agents.mapper import (  # noqa: E402
    english_description,
    find_text_cases,
    join_mappings,
    load_alias_rows,
    osv_listed,
    osv_not_listed,
)
from sibyl.agents.matcher import case_id_for, evaluate, load_candidates  # noqa: E402
from sibyl.agents.reporter import to_markdown  # noqa: E402
from sibyl.agents.scout import classify  # noqa: E402
from sibyl.config import load_settings  # noqa: E402
from sibyl.inventory.schema import DEMO_WORKSPACE  # noqa: E402
from sibyl.llm.client import LLMClient, LLMUnavailable  # noqa: E402
from sibyl.orchestrator.log import RunLog  # noqa: E402
from sibyl.orchestrator.receipts import remember_calls  # noqa: E402
from sibyl.orchestrator.run import Bundle, Clock, run_triage  # noqa: E402
from sibyl.scoring import cvss_by_case  # noqa: E402
from sibyl.tools.collectors import ingest  # noqa: E402
from sibyl.tools.zetaris import ResultTruncated, run_sql, sql_actor, tracing_sql  # noqa: E402


class RecordingLLM:
    """Forwards to Nightshift and keeps every receipt, including a failed attempt.

    Each kept receipt is also one `run_events` row when a run log is attached.
    """

    def __init__(self, inner: LLMClient, log: RunLog | None = None):
        self.inner = inner
        self.log = log
        self.receipts: list[dict] = []

    def complete(self, lane, messages, schema):
        try:
            done = self.inner.complete(lane, messages, schema)
        except LLMUnavailable as exc:
            remember_calls(self.receipts, exc.receipts, schema, self.log)
            raise
        remember_calls(self.receipts, tuple(done.attempts) + (done.receipt,), schema, self.log)
        return done


_FIXTURE_SNAPSHOTS = ROOT / "tests" / "fixtures" / "snapshots"
_CVE_ID = re.compile(r"^CVE-\d{4}-\d+$")
_NVD_BATCH = 20


def main(argv: list[str] | None = None) -> int:
    # Read this before load_settings(), which fills SNAPSHOT_DIR from .env.
    # A command-line SNAPSHOT_DIR is the full set or the subset. A bare
    # fixtures run stays on the frozen fixtures.
    process_snapshot = os.environ.get("SNAPSHOT_DIR", "").strip()
    parser = argparse.ArgumentParser(description="Run a headless Sibyl triage.")
    parser.add_argument("--label", required=True)
    parser.add_argument("--request", default="weekly triage over all services")
    parser.add_argument("--snapshot-dir", default=None)
    args = parser.parse_args(argv)
    started = time.perf_counter()
    snapshot = args.snapshot_dir or process_snapshot or str(_FIXTURE_SNAPSHOTS)
    print(f"snapshot {snapshot}")
    settings = load_settings().model_copy(
        update={"sample_mode": True, "snapshot_dir": snapshot, "workspace_id": DEMO_WORKSPACE}
    )
    if args.label == "fixtures-degraded" and "osv" not in settings.disabled_sources():
        settings = settings.model_copy(update={"disable_sources": "osv"})
    _prepare(settings)
    disabled = sorted(settings.disabled_sources())
    with LLMClient(settings) as client:
        timer = Clock()
        log = RunLog(settings)
        log.start(
            {"kind": "triage", "label": args.label},
            {"max_tokens": settings.run_max_tokens, "max_seconds": settings.run_max_seconds},
        )
        recorder = RecordingLLM(client, log)
        plan = classify(args.request, llm=recorder)
        print(f"intent {plan.intent} cve {plan.cve_id} by {plan.classified_by}")
        zetaris_receipts: list[dict] = []
        log.transition("PLANNED", "COLLECTING")
        with tracing_sql(log, zetaris_receipts):
            cases = _bundles(
                settings,
                recorder,
                disabled,
                plan.cve_id if plan.intent == "point_question" else None,
                trace=log,
            )
        report = run_triage(
            cases,
            settings=settings,
            llm=recorder,
            log=log,
            clock=timer,
            precollected=True,
            receipts={"zetaris": zetaris_receipts, "llm": recorder.receipts},
        )
        events = log.events()
    report.receipts["zetaris"] = zetaris_receipts
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


def _bundles(
    settings,
    llm,
    disabled: list[str],
    only_cve: str | None,
    hmem=None,
    trace: RunLog | None = None,
    *,
    services: set[str] | None = None,
    planner=None,
) -> list[Bundle]:
    """Collect and map the cases. A planner names the cases whose verdict an earlier run keeps.

    Those cases skip the Matcher's text reading here; `run_triage` reuses them.
    """
    loaded = load_candidates(settings)
    if trace is not None and trace.run_id:
        trace.transition("COLLECTING", "MAPPING")
    if hmem is not None:
        loaded_rows = join_mappings(loaded.rows, hmem.snapshot().get("mappings") or [])
    else:
        loaded_rows = loaded.rows
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in loaded_rows:
        if services is not None and str(row.get("service_id") or "") not in services:
            continue
        grouped[case_id_for(row)].append(row)
    observations = find_text_cases(settings)
    if services is not None:
        observations = [case for case in observations if case.service_id in services]
    if only_cve:
        grouped = {key: rows for key, rows in grouped.items() if only_cve in key}
        observations = [case for case in observations if case.vuln_id == only_cve]
    listed = osv_listed(settings)
    aliases = load_alias_rows(settings)
    descriptions = _nvd_text(settings, _case_cves(grouped, observations))
    severities = _severities(settings, _case_cves(grouped, observations))
    siblings = _affected_siblings(grouped)
    bundles: list[Bundle] = []
    ids = list(grouped)
    for case in observations:
        if case.case_id not in grouped:
            ids.append(case.case_id)
    by_case = {item.case_id: item for item in observations}
    for case_id in ids:
        rows = grouped.get(case_id, [])
        observation = by_case.get(case_id)
        head = rows[0] if rows else {}
        package = (observation.package if observation else "") or str(head.get("package") or "")
        version = (observation.version if observation else "") or str(head.get("version") or "")
        vuln = (observation.vuln_id if observation else "") or str(head.get("cve_id") or head.get("vuln_id") or "")
        purl = str(head.get("purl") or (observation and f"pkg:{observation.ecosystem}/{observation.package}@{observation.version}") or "")
        score, cvss_source, cvss_version = severities.get(vuln, (0.0, "", ""))
        service = str(head.get("service_id") or (observation.service_id if observation else ""))
        bundles.append(
            Bundle(
                case_id=case_id,
                rows=[dict(row) for row in rows],
                package=package,
                version=version,
                vuln_id=vuln,
                ecosystem=str(head.get("ecosystem") or (observation.ecosystem if observation else "")),
                description=(observation.text if observation else "") or descriptions.get(vuln, ""),
                record_id=observation.record_id if observation else "",
                disabled=disabled,
                osv_not_listed=osv_not_listed(purl, vuln, listed, aliases) if purl and vuln else False,
                internet_facing=str(head.get("internet_facing") or "").lower() in {"true", "t", "1"},
                criticality=float(head.get("criticality") or 0),
                # KEV and EPSS reach the case through Zetaris REST tables, not the
                # evidence ingest, so a disabled source is dropped here too.
                exploited=bool(head.get("kev_date_added")) and "kev" not in disabled,
                epss_percentile=0.0 if "epss" in disabled else float(head.get("epss_percentile") or 0),
                cvss=score,
                cvss_source=cvss_source,
                cvss_version=cvss_version,
                purl=purl,
                siblings=[name for name in siblings.get((service, vuln), []) if name != package],
            )
        )
    skip = planner.reusable(bundles) if planner is not None else set()
    evaluated = evaluate(loaded.rows, [item for item in observations if item.case_id not in skip], llm=llm)
    drafts = {
        verdict.case_id: verdict
        for verdict in evaluated.result.verdicts
        if verdict.method in {"text_llm", "quarantine"}
    }
    for bundle in bundles:
        draft = drafts.get(bundle.case_id)
        bundle.quote = evaluated.quotes.get(bundle.case_id, "")
        bundle.applies_to_package = evaluated.applies.get(bundle.case_id)
        bundle.text_bound = evaluated.bounds.get(bundle.case_id, "")
        if draft is not None:
            bundle.method = draft.method
            bundle.verdict = draft.verdict
            if draft.verdict == "not_affected" and bundle.siblings:
                bundle.related_affected = bundle.siblings[0]
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


def _case_cves(grouped: dict[str, list[dict[str, str]]], observations) -> list[str]:
    found: set[str] = set()
    for rows in grouped.values():
        if not rows:
            continue
        found.add(str(rows[0].get("cve_id") or rows[0].get("vuln_id") or ""))
    for case in observations:
        found.add(case.vuln_id)
    return sorted(cve for cve in found if _CVE_ID.fullmatch(cve))


def _nvd_text(settings, cve_ids: list[str]) -> dict[str, str]:
    """English NVD descriptions for this run's CVEs, through Zetaris.

    Each batch is paged when `truncated` is set, so a full page is not
    treated as the whole answer.
    """
    with sql_actor("mapper"):
        found: dict[str, str] = {}
        for start in range(0, len(cve_ids), _NVD_BATCH):
            found.update(_nvd_batch(settings, cve_ids[start : start + _NVD_BATCH]))
        return found


def _nvd_batch(settings, cve_ids: list[str]) -> dict[str, str]:
    quoted = ", ".join(f"'{cve}'" for cve in cve_ids)
    found: dict[str, str] = {}
    last = ""
    while True:
        page = f" AND source_id > '{last}'" if last else ""
        loaded = run_sql(
            "SELECT source_id, raw_json FROM evidence.source_records "
            f"WHERE source = 'nvd' AND source_id IN ({quoted}){page} "
            "ORDER BY source_id",
            settings=settings,
            limit=1000,
        )
        for row in loaded.rows:
            source_id = row.get("source_id") or ""
            if source_id not in cve_ids:
                continue
            text = english_description("nvd", row.get("raw_json") or "")
            if text:
                found[source_id] = text
        if not loaded.truncated:
            return found
        nxt = (loaded.rows[-1].get("source_id") or "") if loaded.rows else ""
        if not nxt or nxt == last:
            raise ResultTruncated(f"NVD descriptions for {len(cve_ids)} CVEs did not advance")
        last = nxt


_VULN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,80}$")


def _severities(settings, cve_ids: list[str]) -> dict[str, tuple[float, str, str]]:
    """CVSS base score per CVE, including scores stored under an alias id."""
    safe = [cve for cve in cve_ids if _VULN_ID.fullmatch(cve)]
    if not safe:
        return {}
    alias_rows: list[dict] = []
    with sql_actor("prioritiser"):
        for start in range(0, len(safe), 40):
            alias_rows.extend(_alias_batch(settings, safe[start : start + 40]))
        wanted = _linked_ids(safe, alias_rows)
        severity_rows: list[dict] = []
        for start in range(0, len(wanted), 40):
            severity_rows.extend(_severity_batch(settings, wanted[start : start + 40]))
    return cvss_by_case(safe, alias_rows, severity_rows)


def _linked_ids(case_ids: list[str], alias_rows: list[dict]) -> list[str]:
    """Case ids plus the alias on the other side of each matching pair."""
    wanted = set(case_ids)
    found = set(case_ids)
    for row in alias_rows:
        left = str(row.get("vuln_id") or "").strip()
        right = str(row.get("alias_id") or "").strip()
        if left in wanted and _VULN_ID.fullmatch(right):
            found.add(right)
        if right in wanted and _VULN_ID.fullmatch(left):
            found.add(left)
    return sorted(found)


def _alias_batch(settings, ids: list[str]) -> list[dict]:
    quoted = ", ".join(f"'{item}'" for item in ids)
    by_vuln = _read_all(
        settings,
        "SELECT vuln_id, alias_id FROM evidence.vuln_aliases "
        f"WHERE vuln_id IN ({quoted}) ORDER BY vuln_id, alias_id",
    )
    by_alias = _read_all(
        settings,
        "SELECT vuln_id, alias_id FROM evidence.vuln_aliases "
        f"WHERE alias_id IN ({quoted}) ORDER BY alias_id, vuln_id",
    )
    return by_vuln + by_alias


def _severity_batch(settings, ids: list[str]) -> list[dict]:
    quoted = ", ".join(f"'{item}'" for item in ids)
    return _read_all(
        settings,
        "SELECT record_id, vuln_id, source, score, version FROM evidence.severities "
        f"WHERE vuln_id IN ({quoted}) ORDER BY record_id",
    )


def _read_all(settings, statement: str) -> list[dict]:
    loaded = run_sql(statement, settings=settings, limit=2000)
    if loaded.truncated:
        raise ResultTruncated(f"severity lookup returned {len(loaded.rows)} rows and was cut off")
    return loaded.rows


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
