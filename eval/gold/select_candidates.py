"""Pick the 40 gold pairs from the full-set run. No labels are written.

Pairs are bucketed from what the sources said (the `positions` on each case
and the B1 rows), never from Sibyl's verdict. The labels in gold.jsonl come
from upstream fix commits and release history, checked by hand.

Buckets and quotas follow docs/project/evaluation.md:
- straightforward (15): GHSA, OSV and NVD all present and agree
- nvd_gap (10): no NVD position and no B1 row (no usable CPE)
- range_conflict (8): the sources or B1 disagree, or NVD says affected and OSV does not list it
- text_only (4): no structured range; opened from CVE.org or NVD prose
- special (3): a withdrawn record or a KEV-listed CVE

Within a bucket, cases are ordered by sha256 of the case id and taken round
robin across services, at most one per (package, version, vuln) and two per package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "output_examples" / "full" / "report.json"
BASELINES = ROOT / "eval" / "results" / "baselines-full.jsonl"
OUT = ROOT / "eval" / "gold" / "candidates.jsonl"

QUOTAS = {
    "straightforward": 15,
    "nvd_gap": 10,
    "range_conflict": 8,
    "text_only": 4,
    "special": 3,
}
# Scarce buckets pick first so the package caps do not starve them.
PICK_ORDER = ("special", "text_only", "range_conflict", "nvd_gap", "straightforward")
# Straightforward pairs where every source says not affected, so precision is tested.
STRAIGHT_NOT_AFFECTED = 4
# The worked example in the eval notes: the NVD CPE bound is a typo.
PINNED = {"case:internal-admin:pkg:npm/validator@13.7.0:CVE-2025-56200"}
# Cases upstream cannot settle. Each is skipped and the next case in its bucket is taken.
EXCLUDED = {
    "case:reporting-worker:pkg:pypi/pyjwt@2.8.0:CVE-2025-45768": (
        "disputed by the supplier; the GHSA is unreviewed, so whether it is a vulnerability is open"
    ),
}
# Text-only hits repeat one package (requests matched in axios prose); keep them distinct.
PACKAGE_CAP = {"text_only": 1}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write eval/gold/candidates.jsonl.")
    parser.add_argument("--report", type=Path, default=REPORT)
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args(argv)
    report = json.loads(args.report.read_text(encoding="utf-8"))
    cases = [case for key in ("ranked", "closed", "needs_human") for case in report[key]]
    b1 = _b1_pairs()
    pools: dict[str, list[dict]] = defaultdict(list)
    for case in cases:
        bucket = bucket_of(case, b1)
        if bucket and case["case_id"] not in EXCLUDED:
            pools[bucket].append(case)
    picked: dict[str, list[dict]] = {}
    used_pairs: set[tuple] = set()
    used_packages: dict[str, int] = defaultdict(int)
    for bucket in PICK_ORDER:
        quota = QUOTAS[bucket]
        pool = sorted(pools[bucket], key=lambda c: (c["case_id"] not in PINNED, _digest(c)))
        if bucket == "straightforward":
            negatives = [c for c in pool if _all_say(c, "not_affected")]
            positives = [c for c in pool if _all_say(c, "affected")]
            chosen = _take(negatives, STRAIGHT_NOT_AFFECTED, used_pairs, used_packages, 2)
            chosen += _take(positives, quota - len(chosen), used_pairs, used_packages, 2)
        else:
            cap = PACKAGE_CAP.get(bucket, 2)
            chosen = _take(pool, quota, used_pairs, used_packages, cap)
        if len(chosen) < quota:
            raise SystemExit(f"{bucket}: only {len(chosen)} of {quota} candidates")
        picked[bucket] = [_row(case, bucket, b1) for case in chosen]
    rows = [row for bucket in QUOTAS for row in picked[bucket]]
    with args.out.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print(f"wrote {args.out.relative_to(ROOT)} ({len(rows)} pairs)")
    for bucket in QUOTAS:
        print(f"  {bucket}: pool {len(pools[bucket])}, picked {QUOTAS[bucket]}")
    return 0


def bucket_of(case: dict, b1: dict[tuple, str]) -> str | None:
    positions = case["positions"]
    if case["method"] == "text_llm" or not positions:
        return "text_only"
    if case["exploited"] or any(p.get("status") == "withdrawn" for p in positions):
        return "special"
    verdicts = {p["verdict"] for p in positions}
    service, purl, vuln = _key(case)
    # B1 reads the NVD CPE bounds; the case's NVD position can come from the prose instead.
    b1_says = b1.get((service, purl, vuln))
    if len(verdicts) > 1 or (b1_says and b1_says not in verdicts):
        return "range_conflict"
    sources = {p["source"] for p in positions}
    if "nvd" not in sources and (service, purl, vuln) not in b1 and {"ghsa", "osv"} <= sources:
        return "nvd_gap"
    if {"ghsa", "osv", "nvd"} <= sources:
        return "straightforward"
    return None


def _take(
    pool: list[dict], count: int, used_pairs: set, used_packages: dict, cap: int
) -> list[dict]:
    # A package's first case in the pool goes ahead of its repeats.
    seen: set[str] = set()
    firsts = [c for c in pool if c["package"] not in seen and not seen.add(c["package"])]
    pool = firsts + [c for c in pool if c not in firsts]
    by_service: dict[str, list[dict]] = defaultdict(list)
    for case in pool:
        by_service[_key(case)[0]].append(case)
    chosen: list[dict] = []
    in_bucket: dict[str, int] = defaultdict(int)
    while len(chosen) < count and any(by_service.values()):
        for service in sorted(by_service):
            queue = by_service[service]
            while queue:
                case = queue.pop(0)
                pair = (case["package"], case["version"], case["vuln_id"])
                package = case["package"]
                if pair in used_pairs or used_packages[package] >= 2 or in_bucket[package] >= cap:
                    continue
                used_pairs.add(pair)
                used_packages[package] += 1
                in_bucket[package] += 1
                chosen.append(case)
                break
            if len(chosen) == count:
                break
    return chosen


def _row(case: dict, bucket: str, b1: dict[tuple, str]) -> dict:
    service, purl, vuln = _key(case)
    return {
        "case_id": case["case_id"],
        "service_id": service,
        "purl": purl,
        "vuln_id": vuln,
        "bucket": bucket,
        "positions": case["positions"],
        "record_ids": case["record_ids"],
        "b1": b1.get((service, purl, vuln)),
        "label": None,
    }


def _key(case: dict) -> tuple[str, str, str]:
    # case:<service>:<purl>:<vuln>; the purl itself contains colons.
    body = case["case_id"].removeprefix("case:")
    service, rest = body.split(":", 1)
    purl, vuln = rest.rsplit(":", 1)
    return service, purl, vuln


def _all_say(case: dict, verdict: str) -> bool:
    return all(p["verdict"] == verdict for p in case["positions"])


def _digest(case: dict) -> str:
    return hashlib.sha256(case["case_id"].encode()).hexdigest()


def _b1_pairs() -> dict[tuple, str]:
    pairs = {}
    for line in BASELINES.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row["baseline"] == "B1":
            pairs[(row["service_id"], row["purl"], row["vuln_id"])] = row["prediction"]
    return pairs


if __name__ == "__main__":
    raise SystemExit(main())
