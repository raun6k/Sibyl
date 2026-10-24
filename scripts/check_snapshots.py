"""Parse snapshot files with the collectors and write nothing to Postgres.

Prints, per source, files read, records, parse failures, and value shapes
the frozen fixtures do not already contain. Files modified in the last two
minutes are skipped: the download may still be writing them.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sibyl.config import Settings  # noqa: E402
from sibyl.tools.collectors import COLLECTORS  # noqa: E402
from sibyl.tools.collectors.base import RawRecord, SourceError  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "snapshots"
SHAPE_KINDS = (
    "affected_keys",
    "range_types",
    "severity_types",
    "cvss_versions",
    "ghsa_range_syntax",
    "cpe_match_keys",
    "versions_entry",
)
_CVSS_TYPE = {
    "CVSS_V2": "2.0",
    "CVSS_V3": "3.x",
    "CVSS_V4": "4.0",
    "cvss_v2": "2.0",
    "cvss_v3": "3.1",
    "cvss_v4": "4.0",
    "cvssMetricV2": "2.0",
    "cvssMetricV30": "3.0",
    "cvssMetricV31": "3.1",
    "cvssMetricV40": "4.0",
    "cvssV2_0": "2.0",
    "cvssV3_0": "3.0",
    "cvssV3_1": "3.1",
    "cvssV4_0": "4.0",
}


def ghsa_range_syntax(text: str) -> str:
    """Collapse a GHSA range to its operator shape, ignoring version text and spacing."""
    collapsed = " ".join(text.strip().split())
    if not collapsed:
        return "empty"
    signature = re.sub(r"v?\d[0-9A-Za-z.+_-]*", "V", collapsed)
    signature = re.sub(r"\s*\|\|\s*", "||", signature)
    signature = re.sub(r"\s*([<>=|,]+)\s*", r"\1", signature)
    return signature


def cvss_version(vector: object, type_name: object = None) -> str:
    if isinstance(vector, str):
        if vector.startswith("CVSS:"):
            head = vector.split("/", 1)[0]
            if ":" in head:
                return head.split(":", 1)[1]
        if vector.startswith("AV:"):
            return "2.0"
    if isinstance(type_name, str):
        return _CVSS_TYPE.get(type_name, "")
    return ""


def collect_shapes(source: str, records: list[RawRecord]) -> dict[str, dict[str, str]]:
    """Map each observed shape value to the first file that showed it."""
    found: dict[str, dict[str, str]] = {kind: {} for kind in SHAPE_KINDS}

    def add(kind: str, value: object, origin: str) -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text:
            return
        found[kind].setdefault(text, origin or "?")

    for raw in records:
        origin = raw.origin or raw.source_id
        body = raw.body if isinstance(raw.body, dict) else {}
        if source == "osv":
            _osv_shapes(body, origin, add)
        elif source == "ghsa":
            _ghsa_shapes(body, origin, add)
        elif source == "nvd":
            _nvd_shapes(body, origin, add)
        elif source == "cve_org":
            _cve_shapes(body, origin, add)
    return found


def new_shapes(
    baseline: dict[str, dict[str, str]],
    observed: dict[str, dict[str, str]],
) -> list[tuple[str, str, str]]:
    novel: list[tuple[str, str, str]] = []
    for kind in SHAPE_KINDS:
        known = baseline.get(kind, {})
        for value, origin in sorted(observed.get(kind, {}).items()):
            if value not in known:
                novel.append((kind, value, origin))
    return novel


def _osv_shapes(body: dict, origin: str, add) -> None:
    for affected in body.get("affected") or []:
        if not isinstance(affected, dict):
            add("affected_keys", type(affected).__name__, origin)
            continue
        for key in affected:
            add("affected_keys", key, origin)
        for rng in affected.get("ranges") or []:
            if isinstance(rng, dict):
                add("range_types", str(rng.get("type") or ""), origin)
        for version in affected.get("versions") or []:
            if isinstance(version, dict):
                add("versions_entry", "object:" + ",".join(sorted(version)), origin)
            elif not isinstance(version, str):
                add("versions_entry", type(version).__name__, origin)
    for item in body.get("severity") or []:
        if not isinstance(item, dict):
            continue
        add("severity_types", str(item.get("type") or ""), origin)
        add("cvss_versions", cvss_version(item.get("score"), item.get("type")), origin)


def _ghsa_shapes(body: dict, origin: str, add) -> None:
    for vuln in body.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        raw_range = vuln.get("vulnerable_version_range")
        if isinstance(raw_range, str):
            add("ghsa_range_syntax", ghsa_range_syntax(raw_range), origin)
        elif raw_range is not None:
            add("ghsa_range_syntax", "type:" + type(raw_range).__name__, origin)
    block = body.get("cvss_severities") or {}
    if isinstance(block, dict):
        for key, metric in block.items():
            vector = metric.get("vector_string") if isinstance(metric, dict) else None
            add("cvss_versions", cvss_version(vector, key), origin)


def _nvd_shapes(body: dict, origin: str, add) -> None:
    cve = body.get("cve") if isinstance(body.get("cve"), dict) else {}
    for config in cve.get("configurations") or []:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if isinstance(match, dict):
                    for key in match:
                        add("cpe_match_keys", key, origin)
    metrics = cve.get("metrics") or {}
    if isinstance(metrics, dict):
        for key, items in metrics.items():
            add("cvss_versions", _CVSS_TYPE.get(key, ""), origin)
            if not isinstance(items, list):
                continue
            for item in items:
                data = item.get("cvssData") if isinstance(item, dict) else None
                if isinstance(data, dict):
                    add("cvss_versions", cvss_version(data.get("vectorString"), data.get("version")), origin)


def _cve_shapes(body: dict, origin: str, add) -> None:
    containers = body.get("containers") or {}
    cna = containers.get("cna") if isinstance(containers, dict) else None
    if not isinstance(cna, dict):
        return
    for item in cna.get("affected") or []:
        if isinstance(item, dict):
            for key in item:
                add("affected_keys", key, origin)
            for version in item.get("versions") or []:
                if isinstance(version, dict):
                    add("versions_entry", "object:" + ",".join(sorted(version)), origin)
                elif not isinstance(version, str):
                    add("versions_entry", type(version).__name__, origin)
    _metric_versions(cna.get("metrics"), origin, add)
    for adp in containers.get("adp") or []:
        if isinstance(adp, dict):
            _metric_versions(adp.get("metrics"), origin, add)


def _metric_versions(metrics, origin: str, add) -> None:
    if isinstance(metrics, dict):
        metrics = [metrics]
    if not isinstance(metrics, list):
        return
    for item in metrics:
        if not isinstance(item, dict):
            continue
        for key, data in item.items():
            if key in _CVSS_TYPE or (isinstance(data, dict) and "vectorString" in data):
                vector = data.get("vectorString") if isinstance(data, dict) else None
                version = data.get("version") if isinstance(data, dict) else None
                add("cvss_versions", cvss_version(vector, version or key), origin)


def _settings(directory: Path) -> Settings:
    return Settings(
        sample_mode=True,
        snapshot_dir=str(directory),
        contact_email="snapshots@example.com",
        database_url="",
    )


def scan(directory: Path, *, skip_newer_than: datetime | None) -> dict[str, dict]:
    """Read and normalise one snapshot directory. Does not open Postgres."""
    active = _settings(directory)
    report: dict[str, dict] = {}
    for name, collector in COLLECTORS.items():
        entry = {
            "files_read": [],
            "skipped": [],
            "records": 0,
            "failures": [],
            "shapes": {kind: {} for kind in SHAPE_KINDS},
        }
        try:
            raws, errors = collector.read_snapshot(active, skip_newer_than=skip_newer_than)
        except SourceError as exc:
            entry["failures"].append(str(exc))
            report[name] = entry
            continue
        entry["files_read"] = list(getattr(collector, "files_read", []))
        entry["skipped"] = list(getattr(collector, "skipped_files", []))
        entry["failures"].extend(errors)
        entry["shapes"] = collect_shapes(name, raws)
        normalised = 0
        for raw in raws:
            try:
                collector.normalize(raw)
            except Exception as exc:  # a new shape should be reported, not abort the source
                origin = raw.origin or raw.source_id
                entry["failures"].append(f"{origin}: {exc.__class__.__name__}: {exc}"[:300])
                continue
            normalised += 1
        entry["records"] = normalised
        report[name] = entry
    return report


def _print_source(name: str, entry: dict, novel: list[tuple[str, str, str]]) -> None:
    print(f"{name}")
    print(f"  files read: {len(entry['files_read'])}")
    print(f"  skipped (modified in the last 2 minutes): {len(entry['skipped'])}")
    if entry["skipped"]:
        for filename in entry["skipped"]:
            print(f"    {filename}")
    print(f"  records: {entry['records']}")
    print(f"  parse failures: {len(entry['failures'])}")
    for failure in entry["failures"]:
        print(f"    {failure}")
    if novel:
        print(f"  shapes the fixtures never had: {len(novel)}")
        grouped: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for kind, value, origin in novel:
            grouped[kind].append((value, origin))
        for kind, rows in grouped.items():
            print(f"    {kind}:")
            for value, origin in rows:
                print(f"      {value}  example={origin}")
    else:
        print("  shapes the fixtures never had: none")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Parse snapshots without writing to Postgres.")
    parser.add_argument("--dir", required=True, help="Snapshot directory, laid out like data/sample/snapshots")
    parser.add_argument("--fixtures", default=str(FIXTURES))
    parser.add_argument("--min-age-seconds", type=float, default=120)
    args = parser.parse_args(argv)
    directory = Path(args.dir)
    fixtures = Path(args.fixtures)
    if not directory.is_dir():
        print(f"FAIL check_snapshots: {directory} is not a directory", file=sys.stderr)
        return 1
    cutoff = None
    if args.min_age_seconds > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=args.min_age_seconds)
    print(f"directory {directory}")
    if cutoff is not None:
        print(f"skipping files modified after {cutoff.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    observed = scan(directory, skip_newer_than=cutoff)
    baseline = scan(fixtures, skip_newer_than=None) if fixtures.is_dir() else {}
    skipped = 0
    failures = 0
    for name, entry in observed.items():
        novel = new_shapes(baseline.get(name, {}).get("shapes", {}), entry["shapes"])
        _print_source(name, entry, novel)
        skipped += len(entry["skipped"])
        failures += len(entry["failures"])
    print(f"skipped {skipped} file(s) modified in the last 2 minutes")
    print(f"parse failures {failures}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
