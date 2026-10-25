#!/usr/bin/env python3
"""M3 check for a headless run.

With no arguments, reads output_examples/fixtures and fixtures-degraded.
`--label full` and `--label subset` check those runs, including the
full-set cases. When both labels are given, the case ids, verdicts, and
branches must match. Rationale text may differ.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "output_examples" / "fixtures"
DEGRADED = ROOT / "output_examples" / "fixtures-degraded"

TEXT_CASES = (
    ("internal-admin", "decode-uri-component", "0.2.0", "CVE-2026-45822", "affected"),
    ("checkout-api", "djangorestframework", "3.14.0", "CVE-2024-21520", "affected"),
    ("internal-admin", "xml2js", "0.4.23", "CVE-2023-0842", "affected"),
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a headless Sibyl run.")
    parser.add_argument("--fixtures", type=Path, default=FIXTURES)
    parser.add_argument("--degraded", type=Path, default=DEGRADED)
    parser.add_argument(
        "--allow-range-eval",
        action="store_true",
        help="On the full set the three text CVEs may be range_eval.",
    )
    parser.add_argument(
        "--label",
        action="append",
        choices=("fixtures", "full", "subset"),
        help="Check this run. Repeat to compare full and subset.",
    )
    args = parser.parse_args(argv)
    labels = args.label or ["fixtures"]
    failed = False
    loaded: dict[str, dict] = {}
    try:
        for label in labels:
            directory = _directory(label, args.fixtures)
            report, events = _load(directory)
            loaded[label] = report
            if label == "fixtures":
                _require_done(report, events)
                _require_cases(report, events, allow_range=args.allow_range_eval)
                degraded, degraded_events = _load(args.degraded)
                _require_done(degraded, degraded_events, sendback=False)
                if not degraded.get("degraded"):
                    raise SystemExit("degraded run did not mark the missing source")
                _lower_confidence(report, degraded)
            else:
                _require_done(report, events)
                _require_cases(report, events, allow_range=True)
                _require_full_cases(report, events)
        if "full" in loaded and "subset" in loaded:
            _require_same_branches(loaded["full"], loaded["subset"])
    except SystemExit as exc:
        print(f"FAIL headless: {exc}", file=sys.stderr)
        failed = True
    if failed:
        return 1
    print("PASS headless " + " ".join(labels))
    return 0


def _directory(label: str, fixtures: Path) -> Path:
    if label == "fixtures":
        return fixtures
    return ROOT / "output_examples" / label


def _load(directory: Path) -> tuple[dict, list[dict]]:
    report_path = directory / "report.json"
    trace_path = directory / "trace.jsonl"
    if not report_path.is_file() or not trace_path.is_file():
        raise SystemExit(f"missing report in {directory}")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    events = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return report, events


def _require_done(report: dict, events: list[dict], *, sendback: bool = True) -> None:
    if report.get("state") != "DONE" or report.get("partial"):
        raise SystemExit(f"state {report.get('state')} partial {report.get('partial')}")
    if sendback:
        rechecks = [event for event in events if event.get("type") == "recheck" or (event.get("payload") or {}).get("action") == "recheck"]
        revisions = [event for event in events if event.get("type") == "revision"]
        if not rechecks or not revisions:
            raise SystemExit("no critic send-back with a matcher revision")
    for card in report.get("ranked") or []:
        if not card.get("record_ids"):
            raise SystemExit(f"ranked case {card.get('case_id')} has no record id")
    queries = (report.get("receipts") or {}).get("zetaris") or []
    if not queries:
        raise SystemExit("no Zetaris receipt")
    if not any("v_candidate_matches" in str(query.get("sql") or "") for query in queries):
        raise SystemExit("the core v_candidate_matches query is not in the Zetaris receipts")
    if not any(event.get("type") == "tool" and "v_candidate_matches" in str((event.get("payload") or {}).get("sql") or "") for event in events):
        raise SystemExit("the run log has no Zetaris tool event for v_candidate_matches")
    for receipt in (report.get("receipts") or {}).get("llm") or []:
        if receipt.get("error_code"):
            continue
        if not receipt.get("routed_model"):
            raise SystemExit("an LLM receipt has no routed model")
    blocking = [
        card
        for card in (report.get("ranked") or []) + (report.get("needs_human") or []) + (report.get("closed") or [])
        if any((conflict.get("severity") == "blocking") for conflict in card.get("conflicts") or [])
        and not _resolved(card)
    ]
    if blocking and not report.get("needs_human"):
        raise SystemExit("an unresolved blocking conflict left the needs-human queue empty")


def _resolved(card: dict) -> bool:
    return card.get("verdict") == "affected" and not any(
        conflict.get("severity") == "blocking" for conflict in card.get("conflicts") or []
    )


def _require_cases(report: dict, events: list[dict], *, allow_range: bool) -> None:
    cards = _all(report)
    validator = _one(cards, "internal-admin", "validator", "13.7.0", "CVE-2025-56200")
    if validator.get("verdict") != "affected":
        raise SystemExit(f"validator verdict {validator.get('verdict')}")
    if any(conflict.get("severity") == "blocking" for conflict in validator.get("conflicts") or []):
        raise SystemExit("validator conflict was not resolved")
    if not _sent_back(events, validator["case_id"]):
        raise SystemExit("validator was not sent back and revised")
    axios = _find(cards, "axios", "CVE-2023-45857")
    if not axios or any(card.get("verdict") != "affected" for card in axios):
        raise SystemExit("axios was not left affected")
    if not any(
        conflict.get("severity") == "informational" and (conflict.get("values_by_source") or {}).get("nvd") == "not_affected"
        for card in axios
        for conflict in card.get("conflicts") or []
    ):
        raise SystemExit("axios is missing the informational NVD conflict")
    append = _one(cards, "internal-admin", "append-field", "1.0.0", "CVE-2026-77078")
    multer = _one(cards, "internal-admin", "multer", "1.4.2", "CVE-2026-77078")
    if append.get("verdict") != "not_affected":
        raise SystemExit(f"append-field verdict {append.get('verdict')}")
    if append not in (report.get("closed") or []):
        raise SystemExit("append-field is not closed")
    if "multer" not in str(append.get("accepted_under") or ""):
        raise SystemExit(f"append-field accepted_under {append.get('accepted_under')}")
    if multer.get("verdict") != "affected":
        raise SystemExit(f"multer verdict {multer.get('verdict')}")
    pillow = [
        card
        for card in cards
        if card.get("package") == "pillow" and card.get("vuln_id") == "CVE-2023-4863" and card.get("verdict") == "affected"
    ]
    if not pillow or not any(card.get("exploited") for card in pillow):
        raise SystemExit("affected pillow was not ranked with KEV")
    if not any(card in (report.get("ranked") or []) for card in pillow):
        raise SystemExit("affected pillow is not in the ranked list")
    for service, package, version, vuln, verdict in TEXT_CASES:
        card = _one(cards, service, package, version, vuln)
        if card.get("verdict") != verdict:
            raise SystemExit(f"{package} {vuln} verdict {card.get('verdict')}")
        method = card.get("method") or ""
        allowed = {"text_llm", "range_eval"} if allow_range else {"text_llm"}
        if method not in allowed:
            raise SystemExit(f"{package} {vuln} method {method}")


def _require_full_cases(report: dict, events: list[dict]) -> None:
    cards = _all(report)
    escalated = _escalated(events)
    django = [
        card
        for card in cards
        if "checkout-api" in str(card.get("case_id"))
        and card.get("package") == "django"
        and card.get("version") == "4.2.3"
    ]
    if not django:
        raise SystemExit("no checkout-api django@4.2.3 cases")
    silence = 0
    for card in django:
        if card.get("verdict") != "affected":
            raise SystemExit(f"django {card.get('vuln_id')} verdict {card.get('verdict')}")
        if card["case_id"] in escalated:
            raise SystemExit(f"django {card.get('vuln_id')} was escalated")
        for conflict in card.get("conflicts") or []:
            if conflict.get("field") != "cna_branch":
                continue
            silence += 1
            if conflict.get("severity") != "informational":
                raise SystemExit(f"django {card.get('vuln_id')} CNA silence is {conflict.get('severity')}")
    if silence == 0:
        raise SystemExit("django@4.2.3 has no informational CNA-silence conflict")
    braces = _one(cards, "merchant-portal", "braces", "3.0.2", "CVE-2026-93687")
    if braces not in (report.get("needs_human") or []):
        raise SystemExit("braces CVE-2026-93687 is not needs-human")
    if not any(
        event.get("type") == "decision"
        and (event.get("payload") or {}).get("case_id") == braces["case_id"]
        and (event.get("payload") or {}).get("check") == "withdrawn"
        for event in events
    ):
        raise SystemExit("braces did not go through the withdrawn check")
    _position(braces, "ghsa", status="withdrawn")
    _position(braces, "osv", status="active", verdict="affected")
    _position(braces, "cna", verdict="affected", bound="3.0.3")
    axios = _one(cards, "internal-admin", "axios", "0.21.4", "CVE-2025-58754")
    if axios not in (report.get("needs_human") or []):
        raise SystemExit("axios CVE-2025-58754 is not needs-human")
    _position(axios, "nvd", verdict="affected")
    _position(axios, "osv", verdict="not_listed")
    if any(card.get("package") == "ms" and card.get("vuln_id") == "CVE-2017-20162" for card in report.get("needs_human") or []):
        raise SystemExit("ms CVE-2017-20162 is in needs-human")


def _position(card: dict, source: str, *, verdict: str | None = None, status: str | None = None, bound: str | None = None) -> None:
    found = [item for item in card.get("positions") or [] if item.get("source") == source]
    if len(found) != 1:
        raise SystemExit(f"{card.get('package')} {card.get('vuln_id')} has {len(found)} {source} positions")
    item = found[0]
    if verdict is not None and item.get("verdict") != verdict:
        raise SystemExit(f"{card.get('package')} {source} verdict {item.get('verdict')}")
    if status is not None and item.get("status") != status:
        raise SystemExit(f"{card.get('package')} {source} status {item.get('status')}")
    if bound is not None and item.get("bound") != bound:
        raise SystemExit(f"{card.get('package')} {source} bound {item.get('bound')}")


def _sent_back(events: list[dict], case_id: str) -> bool:
    recheck = False
    revision = False
    for event in events:
        payload = event.get("payload") or {}
        if payload.get("case_id") != case_id:
            continue
        if event.get("type") == "recheck" or payload.get("action") == "recheck":
            recheck = True
        if event.get("type") == "revision":
            revision = True
    return recheck and revision


def _escalated(events: list[dict]) -> set[str]:
    found: set[str] = set()
    for event in events:
        if event.get("type") != "escalation":
            continue
        case_id = str((event.get("payload") or {}).get("case_id") or "")
        if case_id:
            found.add(case_id)
    return found


def _require_same_branches(full: dict, subset: dict) -> None:
    left = _signature(full)
    right = _signature(subset)
    only_full = sorted(set(left) - set(right))
    only_subset = sorted(set(right) - set(left))
    different = sorted(case_id for case_id in set(left) & set(right) if left[case_id] != right[case_id])
    if not only_full and not only_subset and not different:
        return
    lines = ["full and subset do not match"]
    for case_id in only_full:
        lines.append(f"  only full: {case_id} {left[case_id]}")
    for case_id in only_subset:
        lines.append(f"  only subset: {case_id} {right[case_id]}")
    for case_id in different:
        lines.append(f"  {case_id}: full {left[case_id]} subset {right[case_id]}")
    raise SystemExit("\n".join(lines))


def _signature(report: dict) -> dict[str, tuple[str, str]]:
    found: dict[str, tuple[str, str]] = {}
    for branch in ("ranked", "closed", "needs_human"):
        for card in report.get(branch) or []:
            found[str(card.get("case_id"))] = (branch, str(card.get("verdict")))
    return found


def _lower_confidence(normal: dict, degraded: dict) -> None:
    left = {card["case_id"]: card.get("confidence") for card in _all(normal)}
    dropped = False
    for card in _all(degraded):
        before = left.get(card["case_id"])
        if before is None:
            continue
        if card.get("confidence", 1) < before:
            dropped = True
            break
    if not dropped:
        raise SystemExit("degraded run did not lower any confidence")


def _all(report: dict) -> list[dict]:
    return list(report.get("ranked") or []) + list(report.get("closed") or []) + list(report.get("needs_human") or [])


def _one(cards: list[dict], service: str, package: str, version: str, vuln: str) -> dict:
    found = [
        card
        for card in cards
        if service in str(card.get("case_id"))
        and card.get("package") == package
        and card.get("version") == version
        and card.get("vuln_id") == vuln
    ]
    if len(found) != 1:
        raise SystemExit(f"expected one {package}@{version} {vuln}, found {len(found)}")
    return found[0]


def _find(cards: list[dict], package: str, vuln: str) -> list[dict]:
    return [card for card in cards if card.get("package") == package and card.get("vuln_id") == vuln]


if __name__ == "__main__":
    sys.exit(main())
