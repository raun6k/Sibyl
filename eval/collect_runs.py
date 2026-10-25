#!/usr/bin/env python3
"""Live runs the gold-set eval scores. Needs Zetaris, Nightshift and the engines.

Ingests the full snapshots once, then:

1. B1, B2 and B3 over every candidate pair (eval/baselines.py).
2. Sibyl run 1 with H-MEM reset to the seeded trust table.
3. The run-1 needs-human cases that are in the gold set are resolved with
   their reviewed gold label (scope this_case), as a human would.
4. Sibyl run 2 with those resolutions remembered.
5. Sibyl without the critic (CRITIC_ENABLED=false), H-MEM reset again.
6. B4: one deep-lane call per gold pair on the run-1 evidence, no critic,
   no memory.

Runs go to eval/results/runs/<name>/ (report.json, report.md, trace.jsonl,
summary.json). B4 goes to eval/results/b4-full.jsonl. H-MEM is reset when
this finishes, pass or fail. Score them with eval/run_eval.py.

    uv run eval/collect_runs.py
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "eval"))

from run_demo import RecordingLLM, _bundles, _llm_markdown, _llm_stats, _prepare, _summary  # noqa: E402

import baselines  # noqa: E402
from sibyl.agents.reporter import to_markdown  # noqa: E402
from sibyl.config import load_settings  # noqa: E402
from sibyl.engines.hmem import HmemClient  # noqa: E402
from sibyl.engines.world_model import WorldModelClient  # noqa: E402
from sibyl.llm.client import LLMClient, LLMUnavailable, TokenBudget  # noqa: E402
from sibyl.orchestrator.log import RunLog  # noqa: E402
from sibyl.orchestrator.memory import resolve_case  # noqa: E402
from sibyl.orchestrator.run import Bundle, Clock, run_triage  # noqa: E402
from sibyl.tools.zetaris import tracing_sql  # noqa: E402

GOLD = ROOT / "eval" / "gold" / "gold.jsonl"
RUNS = ROOT / "eval" / "results" / "runs"
B4_OUT = ROOT / "eval" / "results" / "b4-full.jsonl"
FULL = ROOT / "data" / "sample" / "snapshots"

B4_PROMPT = """You triage one vulnerability for one installed package.

Decide from the evidence given whether the installed version is affected. The
evidence is every advisory row the sources returned for this package and
vulnerability (OSV, GHSA, NVD, CVE.org), with its range bounds and record
status, plus the advisory description. Use only this evidence.

Output JSON: {"verdict": "affected" | "not_affected" | "uncertain",
"confidence": a JSON number from 0 to 1 written with a leading zero, such as
0.85, "reason": one sentence}.
"""


class SinglePass(BaseModel):
    verdict: Literal["affected", "not_affected", "uncertain"]
    confidence: float = Field(ge=0, le=1)
    reason: str = ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect the live runs for the gold-set eval.")
    parser.add_argument("--snapshot-dir", default=str(FULL))
    parser.add_argument(
        "--max-seconds",
        type=int,
        default=1800,
        help="Per-run time budget. The default 600 can cut a full-set run short.",
    )
    parser.add_argument(
        "--only-b4",
        action="store_true",
        help="Rerun B4 alone on the evidence already ingested, keeping the other runs.",
    )
    args = parser.parse_args(argv)
    settings = load_settings().model_copy(
        update={
            "sample_mode": True,
            "snapshot_dir": args.snapshot_dir,
            "disable_sources": "",
            "run_max_seconds": args.max_seconds,
            "critic_enabled": True,
        }
    )
    gold = [json.loads(line) for line in GOLD.read_text(encoding="utf-8").splitlines() if line]
    if args.only_b4:
        # Text-only cases need the model to build their bundles, as in a run.
        with LLMClient(settings) as client:
            bundles = _bundles(settings, RecordingLLM(client), [], None)
        _single_pass(settings, gold, bundles)
        return 0
    _prepare(settings)
    if baselines.main(["--label", "full"]) != 0:
        raise SystemExit("baselines failed")
    hmem = HmemClient()
    world = WorldModelClient()
    try:
        hmem.reset()
        first, bundles = _run("run1", settings, hmem, world)
        resolved = _resolve(hmem, first, gold)
        (RUNS / "run1" / "resolutions.json").write_text(json.dumps(resolved, indent=2) + "\n", encoding="utf-8")
        _run("run2", settings, hmem, world)
        hmem.reset()
        _run("nocritic", settings.model_copy(update={"critic_enabled": False}), hmem, world)
        _single_pass(settings, gold, bundles)
    finally:
        try:
            hmem.reset()
        finally:
            hmem.close()
            world.close()
    return 0


def _run(name: str, settings, hmem: HmemClient, world: WorldModelClient):
    started = time.perf_counter()
    with LLMClient(settings) as client:
        log = RunLog(settings)
        log.start(
            {"kind": "triage", "label": f"eval-{name}"},
            {"max_tokens": settings.run_max_tokens, "max_seconds": settings.run_max_seconds},
        )
        recorder = RecordingLLM(client, log)
        zetaris: list[dict] = []
        log.transition("PLANNED", "COLLECTING")
        with tracing_sql(log, zetaris):
            cases = _bundles(settings, recorder, [], None, hmem, trace=log)
        kept = copy.deepcopy(cases)
        report = run_triage(
            cases,
            settings=settings,
            llm=recorder,
            log=log,
            clock=Clock(),
            hmem=hmem,
            world=world,
            precollected=True,
        )
        events = log.events()
    report.receipts["zetaris"] = zetaris
    report.receipts["llm"] = recorder.receipts
    wall = round(time.perf_counter() - started, 1)
    out = RUNS / name
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    (out / "report.md").write_text(to_markdown(report) + _llm_markdown(_llm_stats(recorder.receipts)), encoding="utf-8")
    with (out / "trace.jsonl").open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    summary = _summary(report, events, recorder.receipts, wall)
    summary["critic_enabled"] = settings.critic_enabled
    summary["run_max_seconds"] = settings.run_max_seconds
    summary["cases"] = len(report.ranked) + len(report.closed) + len(report.needs_human)
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"{name}: {report.state} partial={report.partial} wall {wall}s tokens {summary['tokens']} branches {summary['branches']}")
    if report.state != "DONE" or report.partial:
        raise SystemExit(f"{name} ended {report.state} partial={report.partial}")
    return report, kept


def _resolve(hmem: HmemClient, report, gold: list[dict]) -> list[dict]:
    """Answer each gold pair in the needs-human queue with its reviewed label."""
    by_case = {_case_id(row): row for row in gold}
    resolved = []
    for card in report.needs_human:
        row = by_case.get(card.case_id)
        if row is None:
            continue
        resolve_case(
            hmem,
            case_id=card.case_id,
            decision=row["label"],
            note=f"Gold {row['id']}: {row['note']}",
            user="raunak",
            remember=True,
            scope="this_case",
            method=card.method,
            ecosystem=card.ecosystem or row["purl"].split(":", 1)[1].split("/", 1)[0],
            package=card.package,
            vuln_id=card.vuln_id,
        )
        resolved.append({"case_id": card.case_id, "gold_id": row["id"], "decision": row["label"]})
    print(f"resolved {len(resolved)} gold cases from the run-1 needs-human queue")
    return resolved


def _single_pass(settings, gold: list[dict], bundles: list[Bundle]) -> None:
    """B4: one deep-lane call per gold pair. No critic, no memory, no second read."""
    by_case = {bundle.case_id: bundle for bundle in bundles}
    started = time.perf_counter()
    # Its own uncapped budget: 40 deep calls can pass the per-run RUN_MAX_TOKENS.
    with LLMClient(settings, budget=TokenBudget(0)) as client:
        recorder = RecordingLLM(client)

        def one(row: dict) -> dict:
            case_id = _case_id(row)
            bundle = by_case.get(case_id)
            base = {"gold_id": row["id"], "case_id": case_id}
            if bundle is None:
                return {**base, "prediction": "missing", "confidence": None, "reason": "no case in run 1"}
            evidence = {
                "package": bundle.package,
                "version": bundle.version,
                "ecosystem": bundle.ecosystem,
                "vuln_id": bundle.vuln_id,
                "rows": [
                    {
                        key: item.get(key)
                        for key in (
                            "source",
                            "record_id",
                            "record_status",
                            "range_type",
                            "introduced",
                            "fixed",
                            "last_affected",
                            "raw_range",
                        )
                        if item.get(key)
                    }
                    for item in bundle.rows
                ],
                "description": bundle.description,
            }
            messages = [
                {"role": "system", "content": B4_PROMPT},
                {"role": "user", "content": json.dumps(evidence)},
            ]
            try:
                done = recorder.complete("deep", messages, SinglePass)
            except LLMUnavailable as exc:
                return {**base, "prediction": "missing", "confidence": None, "reason": f"unavailable: {exc.reason}"}
            return {
                **base,
                "prediction": done.output.verdict,
                "confidence": done.output.confidence,
                "reason": done.output.reason,
                "tokens": done.receipt.tokens,
                "receipt_id": done.receipt.receipt_id,
                "routed_model": done.receipt.routed_model,
            }

        with ThreadPoolExecutor(max_workers=4) as pool:
            rows = list(pool.map(one, gold))
    wall = round(time.perf_counter() - started, 1)
    stats = _llm_stats(recorder.receipts)
    with B4_OUT.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    meta = {"wall_seconds": wall, "tokens": stats["tokens"], "llm_calls": stats["calls"], "lane": "deep"}
    B4_OUT.with_suffix(".summary.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(f"B4: {len(rows)} pairs, wall {wall}s, tokens {stats['tokens']}, calls {stats['calls']}")


def _case_id(row: dict) -> str:
    return f"case:{row['service_id']}:{row['purl']}:{row['vuln_id']}"


if __name__ == "__main__":
    sys.exit(main())
