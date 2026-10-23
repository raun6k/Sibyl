"""Collectors read the frozen fixtures and never the live snapshot directory."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from sibyl.config import Settings
from sibyl.tools.collectors import COLLECTORS
from sibyl.tools.collectors.base import Http, load_json_path
from sibyl.tools.collectors.ghsa import GhsaCollector
from sibyl.tools.collectors.kev import KevCollector

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "snapshots"
SYNTHETIC = ROOT / "tests" / "fixtures" / "synthetic"


def settings(**overrides) -> Settings:
    values = {
        "sample_mode": True,
        "snapshot_dir": str(FIXTURES),
        "contact_email": "tests@example.com",
        "database_url": "",
        "disable_sources": "",
    }
    values.update(overrides)
    return Settings(**values)


def test_each_collector_parses_its_fixture_files():
    active = settings()
    counts = {}
    for name, collector in COLLECTORS.items():
        batch = collector.collect(active)
        assert batch.status == "ok", batch.errors
        assert batch.errors == [], batch.errors
        counts[name] = len(batch.records)
        for record in batch.records:
            assert record.record_id == f"{name}:{record.source_id}"
            assert record.status in {"active", "withdrawn", "rejected"}
    assert counts["osv"] == 40
    assert counts["kev"] == 1754
    assert counts["cve_org"] == 5
    assert counts["euvd"] == 9
    assert counts["ghsa"] == _ghsa_ids()
    assert counts["epss"] == _epss_ids()
    assert counts["nvd"] == _nvd_ids()
    assert counts["ghsa"] > 200
    print("fixture records " + " ".join(f"{name}={count}" for name, count in counts.items()))


def test_osv_normalisation_details():
    batch = COLLECTORS["osv"].collect(settings())
    assert batch.git_ranges_skipped == 1
    record = next(item for item in batch.records if item.source_id == "GHSA-2328-f5f3-gj25")
    assert ("GHSA-2328-f5f3-gj25", "CVE-2026-33896") in record.aliases
    assert ("CVE-2026-33896", "GHSA-2328-f5f3-gj25") in record.aliases
    ecosystems = {row.ecosystem for item in batch.records for row in item.affected}
    assert ecosystems <= {"pypi", "npm"}
    assert all(row.range_type != "GIT" for item in batch.records for row in item.affected)


def test_ghsa_keeps_the_original_range_and_the_patched_version():
    batch = GhsaCollector().collect(settings())
    record = next(item for item in batch.records if item.source_id == "GHSA-2328-f5f3-gj25")
    row = next(item for item in record.affected if item.package == "node-forge")
    assert row.ecosystem == "npm"
    assert row.raw_range == "<= 1.3.3"
    assert row.last_affected == "1.3.3"
    assert row.fixed == "1.4.0"
    scored = next(item for item in record.severities if item.version == "3.1")
    assert scored.vector.startswith("CVSS:3.1/")
    assert scored.score == 7.4


def test_cna_prose_does_not_become_a_range_and_cisa_adp_is_separate():
    batch = COLLECTORS["cve_org"].collect(settings())
    assert sum(len(record.affected) for record in batch.records) == 0
    libwebp = next(record for record in batch.records if record.source_id == "CVE-2023-4863")
    sources = {row.source for row in libwebp.severities}
    assert "cisa-adp" in sources
    assert "cna" not in sources
    lodash = next(record for record in batch.records if record.source_id == "CVE-2020-28500")
    assert any(row.source == "cna" and row.score == 5.3 for row in lodash.severities)


def test_nvd_cpe_rows_and_rejected_status():
    batch = COLLECTORS["nvd"].collect(settings())
    rejected = [record for record in batch.records if record.status == "rejected"]
    assert len(rejected) == 2
    cpe = [row for record in batch.records for row in record.affected if row.range_type == "NVD_CPE"]
    assert cpe
    assert {row.ecosystem for row in cpe} <= {"pypi", "npm", "nvd"}
    assert all(row.raw_range and row.raw_range.startswith("cpe:2.3:") for row in cpe)


def test_euvd_aliases_are_bidirectional():
    batch = COLLECTORS["euvd"].collect(settings())
    record = next(item for item in batch.records if item.source_id == "EUVD-2023-2533")
    assert ("EUVD-2023-2533", "CVE-2023-4863") in record.aliases
    assert ("CVE-2023-4863", "EUVD-2023-2533") in record.aliases


def test_kev_includes_the_libwebp_entry():
    batch = COLLECTORS["kev"].collect(settings())
    assert any(record.source_id == "CVE-2023-4863" for record in batch.records)


def test_malformed_and_empty_synthetic_files_do_not_parse():
    malformed, malformed_error = load_json_path(SYNTHETIC / "malformed.json")
    empty, empty_error = load_json_path(SYNTHETIC / "empty.response")
    assert malformed is None and malformed_error
    assert empty is None and empty_error
    assert "SYNTHETIC" in (SYNTHETIC / "malformed.json").read_text(encoding="utf-8")
    assert "SYNTHETIC" in (SYNTHETIC / "empty.response").read_text(encoding="utf-8")


def test_retry_then_snapshot_fallback_marks_the_source_degraded():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"message": "slow down"})

    active = settings(sample_mode=False)
    http = Http(active, transport=httpx.MockTransport(handler), min_interval=0, sleep=lambda _seconds: None)
    try:
        batch = KevCollector().collect(active, http=http)
    finally:
        http.close()
    assert http.calls == 3
    assert batch.status == "degraded"
    assert len(batch.records) == 1754
    assert batch.errors[0] == "HTTP 429"


def _ghsa_ids() -> int:
    found: set[str] = set()
    for path in (FIXTURES / "ghsa").glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows = payload if isinstance(payload, list) else [payload]
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("ghsa_id"), str):
                found.add(row["ghsa_id"])
    return len(found)


def _epss_ids() -> int:
    found: set[str] = set()
    for path in (FIXTURES / "epss").glob("batch-*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for row in payload.get("data") or []:
            if isinstance(row, dict) and isinstance(row.get("cve"), str):
                found.add(row["cve"])
    return len(found)


def _nvd_ids() -> int:
    found: set[str] = set()
    for path in (FIXTURES / "nvd").glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for item in payload.get("vulnerabilities") or []:
            cve_id = ((item.get("cve") or {}).get("id")) if isinstance(item, dict) else None
            if isinstance(cve_id, str):
                found.add(cve_id)
    return len(found)
