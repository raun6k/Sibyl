#!/usr/bin/env python3
"""Robustness on the frozen fixtures: one outage per source, and idempotency.

Needs Zetaris, Nightshift and the engines. For each of the seven sources a
fixture run is made with that source in DISABLE_SOURCES. Every run must
finish DONE and not partial, with the report marked degraded and the
source's ingest receipt `disabled`. Each source must also show its own
effect against the normal run:

- osv, ghsa: a case decided by a lower-trust source has lower confidence
- cve_org: fewer text-only cases (the ones only CVE.org prose names are lost;
  NVD prose still opens the rest)
- nvd: no NVD position on any case
- kev: no case is exploited
- epss: no case has an EPSS score component
- euvd: completes (EUVD adds aliases and exploited flags only)

Idempotency: re-ingesting the same snapshots reports 0 new and 0 changed for
every source, and a second World Model ingest is an empty diff.

The 429, 5xx and timeout fallbacks are unit tests in tests/test_collectors.py
and prompt injection is in tests/test_orchestrator.py; this check does not
repeat them. Results go to eval/results/robustness.{md,json}.

    uv run tests/robustness_check.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from run_demo import RecordingLLM, _bundles  # noqa: E402
from seed_db import main as seed_main  # noqa: E402

from sibyl.config import load_settings  # noqa: E402
from sibyl.engines.world_model import WorldModelClient  # noqa: E402
from sibyl.llm.client import LLMClient  # noqa: E402
from sibyl.orchestrator.log import RunLog  # noqa: E402
from sibyl.orchestrator.run import Clock, ingest_advisories, run_triage  # noqa: E402
from sibyl.tools.collectors import COLLECTORS, ingest  # noqa: E402
from sibyl.tools.zetaris import tracing_sql  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "snapshots"
RESULTS = ROOT / "eval" / "results"


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Source outages and idempotency on the fixtures.")
    parser.add_argument(
        "--sources",
        nargs="*",
        help="Rerun only these outages (plus the baseline and idempotency) and keep the other rows.",
    )
    args = parser.parse_args(argv)
    base = load_settings().model_copy(
        update={"sample_mode": True, "snapshot_dir": str(FIXTURES), "disable_sources": "", "critic_enabled": True}
    )
    rows: list[dict] = []
    failures: list[str] = []
    normal = _run(base, "none")
    rows.append(normal["row"])
    idempotency = _idempotency(base)
    if not idempotency["passed"]:
        failures.append("idempotency: " + idempotency["detail"])
    kept: dict[str, dict] = {}
    previous = RESULTS / "robustness.json"
    if args.sources and previous.is_file():
        kept = {row["disabled"]: row for row in json.loads(previous.read_text(encoding="utf-8"))["outages"]}
    for source in sorted(COLLECTORS):
        if args.sources and source not in args.sources and source in kept:
            rows.append(kept[source])
            failures.extend(f"{source}: {problem}" for problem in kept[source].get("problems") or [])
            continue
        outage = _run(base.model_copy(update={"disable_sources": source}), source)
        problems = _check(source, outage, normal)
        outage["row"]["passed"] = not problems
        outage["row"]["problems"] = problems
        rows.append(outage["row"])
        failures.extend(f"{source}: {problem}" for problem in problems)
    result = {"outages": rows, "idempotency": idempotency, "passed": not failures, "failures": failures}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "robustness.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (RESULTS / "robustness.md").write_text(_markdown(result), encoding="utf-8")
    print(f"wrote {(RESULTS / 'robustness.md').relative_to(ROOT)}")
    if failures:
        print("FAIL robustness:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 1
    print("PASS robustness")
    return 0


def _run(settings, disabled: str) -> dict:
    if seed_main(["--reset-evidence"]) != 0:
        raise SystemExit("seed failed")
    receipts = {report.source: report.status for report in ingest(settings=settings)}
    started = time.perf_counter()
    with LLMClient(settings) as client:
        log = RunLog(settings)
        log.start({"kind": "triage", "label": f"robustness-{disabled}"}, {"max_tokens": settings.run_max_tokens, "max_seconds": settings.run_max_seconds})
        recorder = RecordingLLM(client, log)
        zetaris: list[dict] = []
        log.transition("PLANNED", "COLLECTING")
        with tracing_sql(log, zetaris):
            cases = _bundles(settings, recorder, sorted(settings.disabled_sources()), None, trace=log)
        report = run_triage(cases, settings=settings, llm=recorder, log=log, clock=Clock(), precollected=True)
    cards = list(report.ranked) + list(report.closed) + list(report.needs_human)
    row = {
        "disabled": disabled,
        "state": report.state,
        "partial": report.partial,
        "degraded": report.degraded,
        "ingest_receipt": receipts.get(disabled, "") if disabled != "none" else "all ok" if all(v == "ok" for v in receipts.values()) else json.dumps(receipts),
        "wall_seconds": round(time.perf_counter() - started, 1),
        "tokens": sum(int(item.get("tokens") or 0) for item in recorder.receipts),
        "cases": len(cards),
        "ranked": len(report.ranked),
        "closed": len(report.closed),
        "needs_human": len(report.needs_human),
        "exploited": sum(card.exploited for card in cards),
        "with_epss": sum(float((card.score_factors or {}).get("epss") or 0) > 0 for card in cards),
        "with_nvd_position": sum(any(p.get("source") == "nvd" for p in card.positions) for card in cards),
        "text_cases": sum(card.method in {"text_llm", "quarantine"} for card in cards),
    }
    return {"row": row, "confidence": {card.case_id: card.confidence for card in cards}}


def _check(source: str, outage: dict, normal: dict) -> list[str]:
    row = outage["row"]
    problems = []
    if row["state"] != "DONE" or row["partial"]:
        problems.append(f"state {row['state']} partial {row['partial']}")
    if not row["degraded"]:
        problems.append("report not marked degraded")
    if row["ingest_receipt"] != "disabled":
        problems.append(f"ingest receipt {row['ingest_receipt']!r}, not 'disabled'")
    lowered = [
        case_id
        for case_id, value in outage["confidence"].items()
        if case_id in normal["confidence"] and value < normal["confidence"][case_id] - 1e-9
    ]
    row["confidence_lowered"] = len(lowered)
    if source in {"osv", "ghsa"} and not lowered:
        problems.append("no case has lower confidence")
    if source == "cve_org" and row["text_cases"] >= normal["row"]["text_cases"]:
        problems.append(f"{row['text_cases']} text-only cases, no fewer than the {normal['row']['text_cases']} normally opened")
    if source == "nvd" and row["with_nvd_position"]:
        problems.append(f"{row['with_nvd_position']} cases still have an NVD position")
    if source == "kev" and row["exploited"]:
        problems.append(f"{row['exploited']} cases still exploited")
    if source == "epss" and row["with_epss"]:
        problems.append(f"{row['with_epss']} cases still have an EPSS component")
    return problems


def _idempotency(settings) -> dict:
    """The evidence from the normal run is still loaded. Ingest it again."""
    again = ingest(settings=settings)
    moved = [f"{r.source} {r.new} new {r.changed} changed" for r in again if r.new or r.changed]
    world = WorldModelClient()
    try:
        first = ingest_advisories(settings, world)
        second = ingest_advisories(settings, world)
    finally:
        world.close()
    empty = second.get("changed") is False and second.get("skippedUnchanged") == second.get("processed")
    detail = []
    if moved:
        detail.append("re-ingest moved rows: " + ", ".join(moved))
    if not empty:
        detail.append(f"second World Model ingest {second}")
    return {
        "passed": not moved and empty,
        "detail": "; ".join(detail),
        "reingest": {r.source: f"{r.new} new, {r.changed} changed, {r.unchanged} unchanged" for r in again},
        "world_model_first": {k: first.get(k) for k in ("processed", "changed", "skippedUnchanged")},
        "world_model_second": {k: second.get(k) for k in ("processed", "changed", "skippedUnchanged")},
    }


def _markdown(result: dict) -> str:
    lines = [
        "# Robustness",
        "",
        f"Overall: {'PASS' if result['passed'] else 'FAIL'}. Fixture runs (`tests/fixtures/snapshots`), written by `tests/robustness_check.py`.",
        "",
        "## Source outage (DISABLE_SOURCES)",
        "",
        "| Disabled | State | Degraded | Ingest receipt | Cases | Ranked / closed / needs human | Confidence lowered | Exploited | EPSS | NVD positions | Text cases | Wall s | Tokens | Check |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in result["outages"]:
        check = "baseline" if row["disabled"] == "none" else ("pass" if row.get("passed") else "FAIL: " + "; ".join(row.get("problems") or []))
        lines.append(
            f"| {row['disabled']} | {row['state']}{' partial' if row['partial'] else ''} | {row['degraded']} | {row['ingest_receipt']} | "
            f"{row['cases']} | {row['ranked']} / {row['closed']} / {row['needs_human']} | {row.get('confidence_lowered', '-')} | "
            f"{row['exploited']} | {row['with_epss']} | {row['with_nvd_position']} | {row['text_cases']} | {row['wall_seconds']} | {row['tokens']} | {check} |"
        )
    idem = result["idempotency"]
    lines += [
        "",
        "## Idempotency",
        "",
        f"{'PASS' if idem['passed'] else 'FAIL'}{': ' + idem['detail'] if idem['detail'] else ''}",
        "",
        "Second ingest of the same snapshots:",
        "",
    ]
    lines += [f"- {source}: {text}" for source, text in idem["reingest"].items()]
    lines += [
        "",
        f"World Model ingest: first {idem['world_model_first']}, second {idem['world_model_second']}.",
        "",
        "## Covered by unit tests",
        "",
        "- 429, 503 and timeout for every source: two retries, then the snapshot, with the source marked degraded "
        "(`tests/test_collectors.py::test_every_source_retries_twice_then_falls_back_to_its_snapshot`).",
        "- Prompt injection: a synthetic NVD description with instructions (`tests/fixtures/synthetic/injected-nvd-description.json`) "
        "is quarantined on a send-back, never reaches the model, and the structured rows decide "
        "(`tests/test_orchestrator.py::test_injected_description_is_quarantined_and_the_rows_decide`). Text-only advisories are "
        "screened before extraction (`tests/test_matcher_text.py::test_quarantined_text_is_not_sent_to_the_model`).",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
