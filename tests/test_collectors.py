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


def test_cna_default_status_is_stored_separately_from_affected_ranges():
    from sibyl.tools.collectors.cve_org import _affected

    rows = _affected(
        {
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "packageName": "django",
                            "collectionURL": "https://pypi.org",
                            "defaultStatus": "unaffected",
                            "versions": [
                                {"version": "5.2", "lessThan": "5.2.18", "status": "affected"},
                                {"version": "4.2", "lessThan": "4.2.4", "status": "unaffected"},
                            ],
                        }
                    ]
                }
            }
        },
        "CVE-2024-1",
    )
    kinds = {row.range_type for row in rows}
    assert kinds == {"CNA", "CNA_UNAFFECTED", "CNA_DEFAULT"}
    assert any(row.raw_range == "default_status=unaffected" for row in rows)


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
    assert counts["osv"] == 44
    assert counts["kev"] == 1754
    assert counts["cve_org"] == 17
    assert counts["euvd"] == 11
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
    # Maven and Go rows are kept since P9; other ecosystems are still dropped.
    assert ecosystems <= {"pypi", "npm", "maven", "golang"}
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
    original = {
        "CVE-2020-28500",
        "CVE-2021-23337",
        "CVE-2022-23539",
        "CVE-2022-37603",
        "CVE-2023-4863",
    }
    prose = [record for record in batch.records if record.source_id in original]
    assert sum(len(record.affected) for record in prose) == 0
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


def test_snapshot_shapes_missing_from_the_first_freeze():
    """Files added after check_snapshots saw shapes the first freeze never had."""
    from sibyl.tools.version_eval import is_affected

    active = settings()
    osv = COLLECTORS["osv"].collect(active)
    immer = next(record for record in osv.records if record.source_id == "GHSA-c36v-fmgq-m8hx")
    score = next(row for row in immer.severities if row.version == "3.0")
    assert score.vector.startswith("CVSS:3.0/")
    assert score.score == 7.5
    ghsa = COLLECTORS["ghsa"].collect(active)
    immer_ghsa = next(record for record in ghsa.records if record.source_id == "GHSA-c36v-fmgq-m8hx")
    ghsa_score = next(row for row in immer_ghsa.severities if row.version == "3.0")
    assert ghsa_score.vector.startswith("CVSS:3.0/")
    assert ghsa_score.score == 7.5
    assert all(row.version != "3.1" for row in immer_ghsa.severities)

    nvd = COLLECTORS["nvd"].collect(active)
    node = next(
        row
        for record in nvd.records
        if record.source_id == "CVE-2022-0778"
        for row in record.affected
        if row.package == "node.js" and row.introduced == "14.0.0"
    )
    assert "start_excluding=14.0.0" in node.raw_range
    bounds = {
        "introduced": node.introduced,
        "fixed": node.fixed,
        "last_affected": node.last_affected,
        "raw_range": node.raw_range,
        "range_type": node.range_type,
    }
    assert is_affected("npm", "14.0.0", [bounds]) is False
    assert is_affected("npm", "14.0.1", [bounds]) is True
    assert is_affected("npm", "14.14.0", [bounds]) is True
    assert is_affected("npm", "14.15.0", [bounds]) is False

    cve = {record.source_id: record for record in COLLECTORS["cve_org"].collect(active).records}
    xml = cve["CVE-2023-0842"].affected[0]
    assert xml.package == "node-xml2js"
    assert xml.introduced == xml.last_affected == "0.4.23"
    assert is_affected("npm", "0.4.23", [_bounds(xml)]) is True
    assert is_affected("npm", "0.4.24", [_bounds(xml)]) is False

    qs = cve["CVE-2025-15284"].affected[0]
    assert qs.package == "qs"
    assert qs.raw_range == "< 6.14.1"
    assert is_affected("npm", "6.7.0", [_bounds(qs)]) is True
    assert is_affected("npm", "6.14.1", [_bounds(qs)]) is False
    assert any(row.version == "4.0" and row.score == 6.3 for row in cve["CVE-2025-15284"].severities)

    multer = cve["CVE-2026-77078"].affected[0]
    assert multer.package == "multer"
    assert multer.introduced == "0"
    assert multer.fixed == "2.3.0"
    assert is_affected("npm", "2.2.0", [_bounds(multer)]) is True
    assert is_affected("npm", "2.3.0", [_bounds(multer)]) is False

    assert cve["CVE-2026-44405"].affected == []
    assert cve["CVE-2023-50782"].affected == []
    assert cve["CVE-2026-45822"].affected == []
    assert any(row.version == "4.0" for row in cve["CVE-2024-21520"].severities)
    assert any(row.version == "3.0" and row.score == 7.5 for row in cve["CVE-2021-3757"].severities)

    micro = cve["CVE-2024-4067"].affected[0]
    assert micro.package == "micromatch" and micro.fixed == "4.0.8"
    braces = cve["CVE-2024-4068"].affected[0]
    assert braces.package == "braces" and braces.last_affected == "3.0.2"
    assert is_affected("npm", "3.0.2", [_bounds(braces)]) is True
    assert is_affected("npm", "3.0.3", [_bounds(braces)]) is False


def _bounds(row) -> dict:
    return {
        "introduced": row.introduced,
        "fixed": row.fixed,
        "last_affected": row.last_affected,
        "raw_range": row.raw_range,
        "range_type": row.range_type,
    }


def test_append_field_is_named_in_text_and_has_no_structured_range():
    active = settings()
    named = {"append-field"}
    for source in ("osv", "ghsa"):
        batch = COLLECTORS[source].collect(active)
        assert all(row.package not in named for record in batch.records for row in record.affected)
    for relative in ("cve/CVE-2026-77078.json", "nvd/cve-CVE-2026-77078.json"):
        text = (FIXTURES / relative).read_text(encoding="utf-8")
        assert "append-field" in text


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


import pytest  # noqa: E402


@pytest.mark.parametrize("source", sorted(COLLECTORS))
@pytest.mark.parametrize("failure", ["429", "503", "timeout"])
def test_every_source_retries_twice_then_falls_back_to_its_snapshot(source, failure, monkeypatch):
    # OSV reads its purls from Postgres; CVE.org has no live fetch and always uses the snapshot.
    monkeypatch.setattr("sibyl.tools.collectors.osv._db_purls", lambda _settings: ["pkg:npm/validator@13.7.0"])
    expected_calls = 0 if source == "cve_org" else 3

    def handler(request: httpx.Request) -> httpx.Response:
        if failure == "timeout":
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(int(failure), json={"message": "synthetic failure"})

    active = settings(sample_mode=False, github_token="", nvd_api_key="")
    http = Http(active, transport=httpx.MockTransport(handler), min_interval=0, sleep=lambda _seconds: None)
    try:
        batch = COLLECTORS[source].collect(active, http=http)
    finally:
        http.close()
    assert http.calls == expected_calls, f"{source} made {http.calls} calls"
    assert batch.status == "degraded"
    assert batch.records, f"{source} fell back to no records"
    assert batch.errors

