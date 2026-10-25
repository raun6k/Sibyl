#!/usr/bin/env python3
"""Two fixture runs. A human resolution and an approved trust change alter the second.

Resets H-MEM to the seeded trust table when it finishes, pass or fail.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from run_demo import RecordingLLM, _bundles, _prepare  # noqa: E402

from sibyl.config import load_settings  # noqa: E402
from sibyl.engines.hmem import HmemClient  # noqa: E402
from sibyl.engines.world_model import WorldModelClient  # noqa: E402
from sibyl.llm.client import LLMClient  # noqa: E402
from sibyl.orchestrator.log import RunLog  # noqa: E402
from sibyl.orchestrator.memory import resolve_case  # noqa: E402
from sibyl.orchestrator.run import run_triage  # noqa: E402
from sibyl.tools.zetaris import tracing_sql  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "snapshots"
DECODE = ("decode-uri-component", "CVE-2026-45822")


def main() -> int:
    settings = load_settings().model_copy(update={"sample_mode": True, "snapshot_dir": str(FIXTURES), "disable_sources": ""})
    _prepare(settings)
    hmem = HmemClient()
    world = WorldModelClient()
    try:
        hmem.reset()
        first, _events = _run(settings, hmem, world)
        needs = list(first.needs_human)
        decode = _one(needs, *DECODE)
        pypi = next(card for card in needs if card.package == "djangorestframework")
        npm = next(
            card
            for card in needs
            if _ecosystem(card) == "npm" and card.case_id != decode.case_id
        )
        npm_before = npm.confidence
        resolve_case(
            hmem,
            case_id=decode.case_id,
            decision="affected",
            note="The prose says through 0.4.1, and 0.2.0 is inside it.",
            user="priya",
            remember=True,
            scope="this_case",
            method=decode.method,
            ecosystem=_ecosystem(decode),
            package=decode.package,
            vuln_id=decode.vuln_id,
        )
        pending = resolve_case(
            hmem,
            case_id=pypi.case_id,
            decision=pypi.verdict or "affected",
            note="Trust the CNA text that named this package.",
            user="priya",
            remember=True,
            scope="adjust_trust",
            method=pypi.method or "text_llm",
            ecosystem=_ecosystem(pypi),
            package=pypi.package,
            vuln_id=pypi.vuln_id,
        )
        change = pending.get("pending") or {}
        if not change.get("id"):
            raise SystemExit("adjust_trust did not create a pending change")
        if change.get("ecosystem") != "pypi":
            raise SystemExit(f"trust change ecosystem {change.get('ecosystem')}")
        if change.get("source") != "cna" or change.get("field") != "affected_ranges":
            raise SystemExit(f"trust change scope {change}")
        approved = hmem.approve(str(change["id"]))
        if not approved.get("ok"):
            raise SystemExit(f"approve failed: {approved}")
        second, second_events = _run(settings, hmem, world)
        if len(second.needs_human) >= len(first.needs_human):
            raise SystemExit(f"needs-human did not fall: {len(first.needs_human)} -> {len(second.needs_human)}")
        remembered = _one(_all(second), *DECODE)
        if remembered.resolution != "memory" or remembered.method != "memory":
            raise SystemExit(f"decode-uri-component resolution {remembered.resolution} method {remembered.method}")
        if any((event.get("payload") or {}).get("case_id") == remembered.case_id and event.get("type") == "escalation" for event in second_events):
            raise SystemExit("the remembered case was escalated again")
        npm_after = _one(_all(second), npm.package, npm.vuln_id)
        if abs(npm_after.confidence - npm_before) > 1e-6:
            raise SystemExit(
                f"pypi trust changed {npm.package} confidence {npm_before} -> {npm_after.confidence}"
            )
        if not _trust_visible(second, 0.9):
            sample = [
                f"{card.package} {card.method} {card.confidence_factors}"
                for card in _all(second)
                if card.verdict == "affected"
            ][:8]
            raise SystemExit("the approved CNA trust change is not in an affected case's confidence factors\n" + "\n".join(sample))
        ingest = second.ingest or {}
        if ingest.get("changed") is not False or not ingest.get("processed") or ingest.get("skippedUnchanged") != ingest.get("processed"):
            raise SystemExit(f"unchanged advisories were not an empty diff: {ingest}")
        print(
            f"PASS memory rerun needs-human {len(first.needs_human)} -> {len(second.needs_human)} "
            f"ingest skipped {ingest.get('skippedUnchanged')}"
        )
        return 0
    finally:
        try:
            hmem.reset()
        finally:
            hmem.close()
            world.close()


def _run(settings, hmem, world):
    with LLMClient(settings) as client:
        log = RunLog(settings)
        log.start({"kind": "triage", "label": "memory"}, {"max_tokens": settings.run_max_tokens, "max_seconds": settings.run_max_seconds})
        recorder = RecordingLLM(client, log)
        receipts: list[dict] = []
        log.transition("PLANNED", "COLLECTING")
        with tracing_sql(log, receipts):
            cases = _bundles(settings, recorder, [], None, hmem, trace=log)
        report = run_triage(
            cases,
            settings=settings,
            llm=recorder,
            log=log,
            hmem=hmem,
            world=world,
            precollected=True,
        )
        events = log.events()
    report.receipts["zetaris"] = receipts
    report.receipts["llm"] = recorder.receipts
    if report.state != "DONE" or report.partial:
        raise SystemExit(f"run {report.state} partial {report.partial}")
    return report, events


def _all(report) -> list:
    return list(report.ranked) + list(report.closed) + list(report.needs_human)


def _one(cards, package: str, vuln: str):
    found = [card for card in cards if card.package == package and card.vuln_id == vuln]
    if len(found) != 1:
        raise SystemExit(f"expected one {package} {vuln}, found {len(found)}")
    return found[0]


def _ecosystem(card) -> str:
    named = str(getattr(card, "ecosystem", "") or "").strip().lower()
    if named and named != "*":
        return named
    case_id = str(card.case_id)
    marker = "pkg:"
    start = case_id.find(marker)
    if start < 0:
        return "*"
    rest = case_id[start + len(marker) :]
    return rest.split("/", 1)[0].lower() or "*"


def _trust_visible(report, weight: float) -> bool:
    pypi = False
    for card in _all(report):
        if card.verdict != "affected" or card.method == "memory":
            continue
        eco = _ecosystem(card)
        for factor in card.confidence_factors:
            if factor.get("name") != "source_trust":
                continue
            if abs(float(factor.get("value") or 0) - weight) > 1e-6:
                continue
            if eco == "npm":
                return False
            if eco == "pypi":
                pypi = True
    return pypi


if __name__ == "__main__":
    sys.exit(main())
