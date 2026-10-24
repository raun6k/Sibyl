#!/usr/bin/env python3
"""M3 check for a headless fixture run.

Reads output_examples/fixtures and output_examples/fixtures-degraded.
A case that comes out differently fails. The three text-only CVEs are
affected with method text_llm on the fixtures. On a full-set run the same
three may be range_eval; pass --allow-range-eval to accept either method.
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
    args = parser.parse_args(argv)
    failed = False
    try:
        report, events = _load(args.fixtures)
        _require_done(report, events)
        _require_cases(report, allow_range=args.allow_range_eval)
        degraded, _events = _load(args.degraded)
        _require_done(degraded, _events, sendback=False)
        if not degraded.get("degraded"):
            raise SystemExit("degraded run did not mark the missing source")
        _lower_confidence(report, degraded)
    except SystemExit as exc:
        print(f"FAIL headless: {exc}", file=sys.stderr)
        failed = True
    if failed:
        return 1
    print("PASS headless")
    return 0


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


def _require_cases(report: dict, *, allow_range: bool) -> None:
    cards = _all(report)
    validator = _one(cards, "internal-admin", "validator", "13.7.0", "CVE-2025-56200")
    if validator.get("verdict") != "affected":
        raise SystemExit(f"validator verdict {validator.get('verdict')}")
    if any(conflict.get("severity") == "blocking" for conflict in validator.get("conflicts") or []):
        raise SystemExit("validator conflict was not resolved")
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
