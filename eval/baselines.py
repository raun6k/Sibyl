"""Baselines B1 and B2.

B1 matches a component when an NVD CPE product name equals the package name
and the CPE version bounds contain the component version. B2 uses OSV ranges
only. Neither reconciles sources.

The fixture label checks that this code runs. It is not an evaluation result:
there is no gold set yet, and the fixture subset was hand-picked.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import psycopg

from sibyl.config import Settings, load_settings
from sibyl.tools.collectors import ingest
from sibyl.tools.version_eval import is_affected
from sibyl.tools.zetaris import ResultTruncated, run_sql

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "snapshots"
RESULTS = ROOT / "eval" / "results"

B1_SQL = """
SELECT
  services.service_id AS service_id,
  components.purl AS purl,
  components.name AS package,
  components.version AS version,
  components.ecosystem AS ecosystem,
  affected.vuln_id AS vuln_id,
  affected.record_id AS record_id,
  affected.range_type AS range_type,
  affected.introduced AS introduced,
  affected.fixed AS fixed,
  affected.last_affected AS last_affected,
  affected.raw_range AS raw_range
FROM acme_internal.components AS components
JOIN acme_internal.sboms AS sboms ON components.sbom_id = sboms.sbom_id
JOIN acme_internal.services AS services ON sboms.service_id = services.service_id
JOIN evidence.affected AS affected
  ON lower(affected.package) = lower(components.name)
WHERE affected.range_type = 'NVD_CPE'
"""

B2_SQL = """
SELECT *
FROM sibyl.v_candidate_matches
WHERE source = 'osv'
"""

DISCLAIMER = (
    "These numbers check that the code works. They are not results. "
    "There is no gold set yet (P5), and the fixture subset is hand-picked."
)
PAGE_LIMIT = 50000
SERVICE_SQL = "SELECT service_id FROM acme_internal.services ORDER BY service_id"
_SERVICE_ID = re.compile(r"^[A-Za-z0-9_-]+$")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Write B1 and B2 baseline predictions.")
    parser.add_argument("--label", default="fixtures")
    args = parser.parse_args(argv)
    loaded = load_settings()
    if args.label == "fixtures":
        active = loaded.model_copy(update={"sample_mode": True, "snapshot_dir": str(FIXTURES)})
        _reset_evidence(active)
        for report in ingest(settings=active):
            print(report.summary())
    else:
        active = loaded
    b1 = _predict(active, "B1", B1_SQL, _b1_key)
    b2 = _predict(active, "B2", B2_SQL, _b2_key)
    RESULTS.mkdir(parents=True, exist_ok=True)
    jsonl_path = RESULTS / f"baselines-{args.label}.jsonl"
    md_path = RESULTS / f"baselines-{args.label}.md"
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for row in b1 + b2:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    md_path.write_text(_summary(args.label, b1, b2), encoding="utf-8")
    print(f"wrote {jsonl_path.relative_to(ROOT)} ({len(b1) + len(b2)} pairs)")
    print(f"wrote {md_path.relative_to(ROOT)}")
    return 0


def _reset_evidence(settings: Settings) -> None:
    """Drop ingested records before a fixture ingest so it cannot mix with a fuller set."""
    sys.path.insert(0, str(ROOT / "scripts"))
    from seed_db import evidence_counts, format_evidence_counts, reset_evidence

    if not settings.database_url:
        raise RuntimeError("DATABASE_URL is empty")
    with psycopg.connect(settings.database_url) as conn:
        before, sources = evidence_counts(conn)
        print(format_evidence_counts("evidence before reset", before, sources))
        reset_evidence(conn)
        after, after_sources = evidence_counts(conn)
        print(format_evidence_counts("evidence after reset", after, after_sources))


def _predict(settings: Settings, baseline: str, sql: str, key_of) -> list[dict]:
    """Read one service at a time. A page that fills the limit is refused."""
    services = run_sql(SERVICE_SQL, settings=settings)
    if services.truncated:
        raise ResultTruncated(f"{baseline} service list reached the row limit")
    rows: list[dict] = []
    for service in services.rows:
        service_id = service.get("service_id") or ""
        if not _SERVICE_ID.fullmatch(service_id):
            raise RuntimeError(f"service_id {service_id!r} is not safe to interpolate")
        page_sql = sql.rstrip().rstrip(";") + f"\nAND service_id = '{service_id}'"
        if "services.service_id" in sql and "AS service_id" in sql:
            page_sql = sql.rstrip().rstrip(";") + f"\nAND services.service_id = '{service_id}'"
        loaded = run_sql(page_sql, settings=settings, limit=PAGE_LIMIT)
        if loaded.truncated:
            raise ResultTruncated(
                f"{baseline} {service_id} returned {len(loaded.rows)} rows, the limit {PAGE_LIMIT}"
            )
        rows.extend(loaded.rows)
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[key_of(row)].append(row)
    predictions = []
    for key, group in sorted(grouped.items()):
        service_id, purl, package, version, vuln_id, ecosystem = key
        ranges = [
            {
                "introduced": row.get("introduced") or None,
                "fixed": row.get("fixed") or None,
                "last_affected": row.get("last_affected") or None,
                "raw_range": row.get("raw_range") or None,
                "range_type": row.get("range_type") or None,
            }
            for row in group
        ]
        decided = is_affected(ecosystem, version, ranges)
        prediction = {True: "affected", False: "not_affected"}.get(decided, "uncertain")
        predictions.append(
            {
                "baseline": baseline,
                "service_id": service_id,
                "purl": purl,
                "package": package,
                "version": version,
                "vuln_id": vuln_id,
                "ecosystem": ecosystem,
                "prediction": prediction,
            }
        )
    return predictions


def _b1_key(row: dict) -> tuple:
    return (
        row.get("service_id", ""),
        row.get("purl", ""),
        row.get("package", ""),
        row.get("version", ""),
        row.get("vuln_id", ""),
        row.get("ecosystem", ""),
    )


def _b2_key(row: dict) -> tuple:
    vuln = row.get("cve_id") or row.get("vuln_id") or ""
    return (
        row.get("service_id", ""),
        row.get("purl", ""),
        row.get("package", ""),
        row.get("version", ""),
        vuln,
        row.get("ecosystem", ""),
    )


def _summary(label: str, b1: list[dict], b2: list[dict]) -> str:
    lines = [
        f"# Baseline results: {label}",
        "",
        DISCLAIMER,
        "",
    ]
    for baseline, rows in (("B1 NVD-CPE-only", b1), ("B2 OSV-only", b2)):
        counts = Counter(row["prediction"] for row in rows)
        by_service = Counter(row["service_id"] for row in rows if row["prediction"] == "affected")
        lines.extend(
            [
                f"## {baseline}",
                "",
                f"- pairs: {len(rows)}",
                f"- predicted affected: {counts['affected']}",
                f"- predicted not affected: {counts['not_affected']}",
                f"- uncertain: {counts['uncertain']}",
                "- predicted affected per service:",
            ]
        )
        if not by_service:
            lines.append("  - none")
        for service, count in sorted(by_service.items()):
            lines.append(f"  - {service}: {count}")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
