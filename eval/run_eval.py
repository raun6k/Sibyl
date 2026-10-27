#!/usr/bin/env python3
"""Score every system against the gold set. Reads files only; no live calls.

Inputs (written by eval/baselines.py and eval/collect_runs.py):
- eval/results/baselines-full.jsonl: B1, B2, B3
- eval/results/b4-full.jsonl: B4 single-pass LLM
- eval/results/runs/{run1,nocritic,run2}/: Sibyl, Sibyl without the critic,
  and Sibyl run 2 after the run-1 resolutions

Writes eval/results/eval-full.json and eval/results/eval-full.md.

Scoring rules:
- Positive class is `affected`. A pair a system never reports counts as
  `not_affected`, which is what a pipeline that does not flag it tells you.
- `uncertain` (any needs-human case, whatever its draft verdict, or a baseline
  that cannot decide) is not a positive. It is wrong for accuracy.
- Confident means confidence >= 0.8.

    uv run eval/run_eval.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOLD = ROOT / "eval" / "gold" / "gold.jsonl"
CANDIDATES = ROOT / "eval" / "gold" / "candidates.jsonl"
RESULTS = ROOT / "eval" / "results"
CONFIDENT = 0.8
SIBYL_RUNS = (("Sibyl", "run1"), ("Sibyl − critic", "nocritic"), ("Sibyl run 2", "run2"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score the systems against the gold set.")
    parser.add_argument("--results", type=Path, default=RESULTS)
    args = parser.parse_args(argv)
    gold = _jsonl(GOLD)
    conflicted = conflict_pairs(gold, _jsonl(CANDIDATES))
    systems: dict[str, dict] = {}
    for name, rows in load_baselines(args.results / "baselines-full.jsonl").items():
        systems[name] = {"predictions": rows}
    b4_path = args.results / "b4-full.jsonl"
    if b4_path.is_file():
        systems["B4 single-pass LLM"] = {"predictions": load_b4(b4_path), "summary": _json(b4_path.with_suffix(".summary.json"))}
    runs: dict[str, dict] = {}
    for name, folder in SIBYL_RUNS:
        directory = args.results / "runs" / folder
        if not (directory / "report.json").is_file():
            continue
        run = load_run(directory)
        runs[folder] = run
        systems[name] = {"predictions": predictions_from_report(run["report"]), "summary": run["summary"]}
    scored = {name: score(gold, system["predictions"]) for name, system in systems.items()}
    for name, folder in SIBYL_RUNS:
        if folder in runs:
            scored[name].update(sibyl_extras(gold, runs[folder], conflicted))
    result = {
        "gold": {"pairs": len(gold), "affected": sum(r["label"] == "affected" for r in gold), "hard": sum(r["hard"] for r in gold)},
        "systems": scored,
        "runtime": {name: _runtime(system.get("summary")) for name, system in systems.items() if system.get("summary")},
    }
    if "run1" in runs and "nocritic" in runs:
        result["critic_effect"] = critic_effect(gold, runs["run1"], runs["nocritic"])
    if "run1" in runs and "run2" in runs:
        result["memory_effect"] = memory_effect(gold, runs["run1"], runs["run2"])
    result["per_pair"] = per_pair(gold, {name: system["predictions"] for name, system in systems.items()})
    (args.results / "eval-full.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (args.results / "eval-full.md").write_text(to_markdown(result), encoding="utf-8")
    print(f"wrote {args.results / 'eval-full.md'}")
    return 0


def case_id(row: dict) -> str:
    return f"case:{row['service_id']}:{row['purl']}:{row['vuln_id']}"


def load_baselines(path: Path) -> dict[str, dict[str, dict]]:
    names = {"B1": "B1 NVD-CPE-only", "B2": "B2 OSV-only", "B3": "B3 naive union"}
    found: dict[str, dict[str, dict]] = {}
    for row in _jsonl(path):
        name = names.get(row["baseline"], row["baseline"])
        found.setdefault(name, {})[case_id(row)] = {"prediction": row["prediction"]}
    return found


def load_b4(path: Path) -> dict[str, dict]:
    return {
        row["case_id"]: {"prediction": row["prediction"], "confidence": row.get("confidence")}
        for row in _jsonl(path)
        if row["prediction"] != "missing"
    }


def load_run(directory: Path) -> dict:
    events_path = directory / "trace.jsonl"
    resolutions = directory / "resolutions.json"
    return {
        "report": _json(directory / "report.json"),
        "events": _jsonl(events_path) if events_path.is_file() else [],
        "summary": _json(directory / "summary.json") if (directory / "summary.json").is_file() else {},
        "resolutions": _json(resolutions) if resolutions.is_file() else [],
    }


def cards(report: dict) -> list[tuple[str, dict]]:
    return [(branch, card) for branch in ("ranked", "closed", "needs_human") for card in report.get(branch) or []]


def predictions_from_report(report: dict) -> dict[str, dict]:
    found = {}
    for branch, card in cards(report):
        # A needs-human case is escalated, not decided, whatever its draft verdict.
        verdict = card.get("verdict") or "uncertain"
        found[card["case_id"]] = {
            "prediction": "uncertain" if branch == "needs_human" else verdict,
            "draft": verdict,
            "confidence": card.get("confidence"),
            "branch": branch,
        }
    return found


def score(gold: list[dict], predictions: dict[str, dict]) -> dict:
    tp = fp = fn = tn = uncertain = missing = correct = 0
    confident = wrong_confident = 0
    for row in gold:
        found = predictions.get(case_id(row))
        if found is None:
            missing += 1
            said = "not_affected"
        else:
            said = found["prediction"]
        if said == "uncertain":
            uncertain += 1
        positive = said == "affected"
        actual = row["label"] == "affected"
        tp += positive and actual
        fp += positive and not actual
        fn += (not positive) and actual
        tn += (not positive) and not actual
        correct += said == row["label"]
        level = (found or {}).get("confidence")
        if level is not None and level >= CONFIDENT:
            confident += 1
            wrong_confident += said != row["label"]
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "uncertain": uncertain,
        "not_reported": missing,
        "recall": _ratio(tp, tp + fn),
        "precision": _ratio(tp, tp + fp),
        "accuracy": _ratio(correct, len(gold)),
        "correct": correct,
        "confident": confident if any("confidence" in item for item in predictions.values()) else None,
        "wrong_confident_rate": _ratio(wrong_confident, confident) if confident else None,
    }


def conflict_pairs(gold: list[dict], candidates: list[dict]) -> set[str]:
    """Gold pairs with a real conflict: the range-conflict bucket and withdrawn records."""
    withdrawn = {
        case_id(row)
        for row in candidates
        if any(position.get("status") in {"withdrawn", "rejected"} for position in row.get("positions") or [])
    }
    return {case_id(row) for row in gold if row["bucket"] == "range_conflict" or case_id(row) in withdrawn}


def sibyl_extras(gold: list[dict], run: dict, conflicted: set[str]) -> dict:
    by_case = {card["case_id"]: (branch, card) for branch, card in cards(run["report"])}
    flagged = _flagged(run["events"])
    hard = {case_id(row) for row in gold if row["hard"]}
    escalated = [case_id(row) for row in gold if by_case.get(case_id(row), ("",))[0] == "needs_human"]
    surfaced = [
        key
        for key in conflicted
        if key in by_case and (by_case[key][1].get("conflicts") or key in flagged or by_case[key][0] == "needs_human")
    ]
    every = [card for _branch, card in cards(run["report"])]
    sourced = [
        card
        for card in every
        if card.get("record_ids") and all(position.get("source") for position in card.get("positions") or [])
    ]
    return {
        "escalated": len(escalated),
        "escalated_hard": sum(key in hard for key in escalated),
        "calibrated_escalation": _ratio(sum(key in hard for key in escalated), len(escalated)),
        "conflicts_in_gold": len(conflicted),
        "conflicts_surfaced": len(surfaced),
        "conflict_detection": _ratio(len(surfaced), len(conflicted)),
        "cases": len(every),
        "cases_with_provenance": len(sourced),
        "provenance_completeness": _ratio(len(sourced), len(every)),
    }


def critic_effect(gold: list[dict], run: dict, ablation: dict) -> dict:
    """Send-backs are cases the critic rechecked in run 1. A change is a verdict that
    differs from the run without the critic."""
    with_critic = predictions_from_report(run["report"])
    without = predictions_from_report(ablation["report"])
    labels = {case_id(row): row["label"] for row in gold}
    sent_back = sorted(_sent_back(run["events"]))
    changed = [key for key in sent_back if key in without and with_critic.get(key, {}).get("prediction") != without[key]["prediction"]]
    branch_moved = [
        key for key in with_critic if key in without and with_critic[key]["branch"] != without[key]["branch"]
    ]
    gold_changes = []
    for key, label in labels.items():
        a = with_critic.get(key, {}).get("prediction", "not_affected")
        b = without.get(key, {}).get("prediction", "not_affected")
        if a != b:
            gold_changes.append({"case_id": key, "with_critic": a, "without_critic": b, "label": label, "fixed": a == label, "broke": b == label})
    full = score(gold, with_critic)
    bare = score(gold, without)
    return {
        "accuracy_delta": _delta(full["accuracy"], bare["accuracy"]),
        "recall_delta": _delta(full["recall"], bare["recall"]),
        "precision_delta": _delta(full["precision"], bare["precision"]),
        "sendbacks": len(sent_back),
        "sendbacks_that_changed_verdict": len(changed),
        "changed_cases": changed,
        "cases_that_changed_branch": len(branch_moved),
        "gold_changes": gold_changes,
    }


def memory_effect(gold: list[dict], first: dict, second: dict) -> dict:
    resolved = {item["case_id"] for item in first.get("resolutions") or []}
    rest = [row for row in gold if case_id(row) not in resolved]
    s1, s2 = first.get("summary") or {}, second.get("summary") or {}
    return {
        "resolved_in_run1": len(resolved),
        "escalations": [s1.get("escalations"), s2.get("escalations")],
        "needs_human": [(s1.get("branches") or {}).get("needs_human"), (s2.get("branches") or {}).get("needs_human")],
        "llm_calls": [s1.get("llm_calls"), s2.get("llm_calls")],
        "tokens": [s1.get("tokens"), s2.get("tokens")],
        "wall_seconds": [s1.get("wall_seconds"), s2.get("wall_seconds")],
        "run2_accuracy_on_unresolved_pairs": score(rest, predictions_from_report(second["report"]))["accuracy"],
        "run1_accuracy_on_unresolved_pairs": score(rest, predictions_from_report(first["report"]))["accuracy"],
        "unresolved_pairs": len(rest),
    }


def per_pair(gold: list[dict], systems: dict[str, dict[str, dict]]) -> list[dict]:
    rows = []
    for row in gold:
        key = case_id(row)
        said = {name: (predictions.get(key) or {"prediction": "missing"})["prediction"] for name, predictions in systems.items()}
        rows.append({"id": row["id"], "pair": f"{row['purl'].split('/', 1)[1]} {row['vuln_id']}", "bucket": row["bucket"], "label": row["label"], "hard": row["hard"], "said": said})
    return rows


def to_markdown(result: dict) -> str:
    g = result["gold"]
    lines = [
        "# Eval: full set against the gold set",
        "",
        f"Gold set: {g['pairs']} pairs, {g['affected']} affected, {g['hard']} hard (`eval/gold/gold.jsonl`).",
        "Positive class is `affected`. A pair a system does not report counts as not affected; "
        "`uncertain` (every needs-human case, whatever its draft verdict) is not a positive and is wrong for accuracy. "
        "Confident means confidence ≥ 0.8.",
        "",
        "## Verdicts",
        "",
        "| System | Recall | Precision | Accuracy | TP | FP | FN | Uncertain | Wrong-confident |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, s in result["systems"].items():
        wrong = "n/a" if s["wrong_confident_rate"] is None else f"{_pct(s['wrong_confident_rate'])} of {s['confident']}"
        lines.append(
            f"| {name} | {_pct(s['recall'])} | {_pct(s['precision'])} | {_pct(s['accuracy'])} | "
            f"{s['tp']} | {s['fp']} | {s['fn']} | {s['uncertain']} | {wrong} |"
        )
    for name, scored in result["systems"].items():
        if scored.get("not_reported"):
            lines += ["", f"{name}: {scored['not_reported']} of {g['pairs']} predictions were not reported. "
                      "The table applies the stated missing-as-not-affected scoring rule; this is not a completed model-quality comparison. "
                      "Token and runtime totals for an incomplete baseline do not support an efficiency ratio."]
    sibyl = {name: s for name, s in result["systems"].items() if "escalated" in s}
    if sibyl:
        lines += [
            "",
            "## Escalation, conflicts, provenance",
            "",
            "| System | Escalated gold pairs | Calibrated escalation | Conflict detection | Provenance completeness |",
            "|---|---|---|---|---|",
        ]
        for name, s in sibyl.items():
            lines.append(
                f"| {name} | {s['escalated']} | {_pct(s['calibrated_escalation'])} ({s['escalated_hard']} hard) | "
                f"{_pct(s['conflict_detection'])} ({s['conflicts_surfaced']} of {s['conflicts_in_gold']}) | "
                f"{_pct(s['provenance_completeness'])} ({s['cases_with_provenance']} of {s['cases']} cases) |"
            )
    effect = result.get("critic_effect")
    if effect:
        lines += [
            "",
            "## Critic effect (Sibyl vs Sibyl − critic)",
            "",
            f"- Accuracy {_signed(effect['accuracy_delta'])}, recall {_signed(effect['recall_delta'])}, precision {_signed(effect['precision_delta'])}.",
            f"- Send-backs in run 1: {effect['sendbacks']}. Send-backs whose verdict differs without the critic: {effect['sendbacks_that_changed_verdict']}.",
            f"- Cases on a different branch (ranked / closed / needs-human): {effect['cases_that_changed_branch']}.",
        ]
        for change in effect["gold_changes"]:
            outcome = "critic right" if change["fixed"] else "critic wrong" if change["broke"] else "both wrong"
            lines.append(f"  - {change['case_id']}: {change['without_critic']} → {change['with_critic']} (label {change['label']}, {outcome})")
    memory = result.get("memory_effect")
    if memory:
        lines += [
            "",
            "## Memory effect (run 1 → run 2)",
            "",
        "Run 2 is a full-retriage memory ablation: it re-evaluates every case after the human answer. "
        "It does not reuse unchanged verdicts, so fresh model judgement can vary on unanswered cases.",
        "",
            f"Run-1 needs-human gold pairs resolved with their reviewed label: {memory['resolved_in_run1']}.",
            "",
            "| | Run 1 | Run 2 |",
            "|---|---|---|",
            f"| Escalations | {memory['escalations'][0]} | {memory['escalations'][1]} |",
            f"| Needs human | {memory['needs_human'][0]} | {memory['needs_human'][1]} |",
            f"| LLM calls | {memory['llm_calls'][0]} | {memory['llm_calls'][1]} |",
            f"| Tokens | {memory['tokens'][0]} | {memory['tokens'][1]} |",
            f"| Wall seconds | {memory['wall_seconds'][0]} | {memory['wall_seconds'][1]} |",
            f"| Accuracy on the {memory['unresolved_pairs']} pairs not resolved | {_pct(memory['run1_accuracy_on_unresolved_pairs'])} | {_pct(memory['run2_accuracy_on_unresolved_pairs'])} |",
        ]
    if result.get("runtime"):
        lines += ["", "## Runtime and tokens", "", "| System | Wall seconds | Tokens | LLM calls | Cases | Tokens per case |", "|---|---|---|---|---|---|"]
        for name, r in result["runtime"].items():
            lines.append(f"| {name} | {r['wall_seconds']} | {r['tokens']} | {r['llm_calls']} | {r['cases']} | {r['tokens_per_case']} |")
    lines += ["", "## Per pair", ""]
    names = list(result["systems"])
    lines.append("| Id | Pair | Bucket | Label | " + " | ".join(names) + " |")
    lines.append("|---|---|---|---|" + "---|" * len(names))
    for row in result["per_pair"]:
        marks = [_mark(row["said"].get(name, "not_affected"), row["label"]) for name in names]
        hard = " (hard)" if row["hard"] else ""
        lines.append(f"| {row['id']} | {row['pair']} | {row['bucket']}{hard} | {row['label']} | " + " | ".join(marks) + " |")
    lines += ["", "✓ correct, ✗ wrong, ? uncertain, — not reported (scored as not affected).", ""]
    return "\n".join(lines)


def _flagged(events: list[dict]) -> set[str]:
    found = set()
    for event in events:
        payload = event.get("payload") or {}
        key = str(payload.get("case_id") or "")
        if not key:
            continue
        if event.get("type") in {"recheck", "escalation"} or payload.get("action") in {"recheck", "reject"}:
            found.add(key)
    return found


def _sent_back(events: list[dict]) -> set[str]:
    return {
        str((event.get("payload") or {}).get("case_id"))
        for event in events
        if event.get("type") == "decision" and (event.get("payload") or {}).get("action") == "recheck"
    }


def _runtime(summary: dict) -> dict:
    cases = summary.get("cases")
    tokens = summary.get("tokens") or 0
    return {
        "wall_seconds": summary.get("wall_seconds"),
        "tokens": tokens,
        "llm_calls": summary.get("llm_calls"),
        "cases": cases if cases is not None else 40,
        "tokens_per_case": round(tokens / (cases or 40), 1),
    }


def _mark(said: str, label: str) -> str:
    if said == "missing":
        return "—"
    if said == "uncertain":
        return "?"
    return "✓" if said == label else "✗"


def _ratio(part: int, whole: int) -> float | None:
    return round(part / whole, 4) if whole else None


def _delta(a: float | None, b: float | None) -> float | None:
    return None if a is None or b is None else round(a - b, 4)


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _signed(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:+.1f} pts"


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    sys.exit(main())
