"""Ingest is idempotent, and a disabled source does not stop the run."""

from __future__ import annotations

from pathlib import Path

import psycopg

from sibyl.config import Settings, load_settings
from sibyl.tools.collectors import ingest

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "snapshots"


def _settings(**overrides) -> Settings:
    loaded = load_settings()
    values = {
        "database_url": loaded.database_url,
        "sample_mode": True,
        "snapshot_dir": str(FIXTURES),
        "contact_email": loaded.contact_email or "tests@example.com",
        "disable_sources": "",
        "nvd_api_key": "",
        "github_token": "",
    }
    values.update(overrides)
    return Settings(**values)


def _counts(url: str) -> tuple[int, int, int, int]:
    with psycopg.connect(url) as conn:
        row = conn.execute(
            """
            SELECT
                (SELECT count(*) FROM evidence.source_records),
                (SELECT count(*) FROM evidence.vuln_aliases),
                (SELECT count(*) FROM evidence.affected),
                (SELECT count(*) FROM evidence.severities)
            """
        ).fetchone()
    return tuple(row)


def test_second_ingest_reports_no_changes():
    active = _settings()
    first = ingest(settings=active)
    after_first = _counts(active.database_url)
    second = ingest(settings=active)
    after_second = _counts(active.database_url)
    assert after_first == after_second
    assert after_first[0] > 0
    for report in second:
        assert report.status == "ok", report.summary()
        assert report.errors == []
        assert report.new == 0 and report.changed == 0
        assert report.unchanged > 0
        assert "0 new, 0 changed" in report.summary()
    first_totals = {report.source: report.new + report.changed + report.unchanged for report in first}
    second_totals = {report.source: report.unchanged for report in second}
    assert first_totals == second_totals
    for report in second:
        print(report.summary())
    print(
        "rows source_records={0} aliases={1} affected={2} severities={3}".format(*after_second)
    )


def test_disabled_nvd_does_not_stop_the_other_sources():
    active = _settings(disable_sources="nvd")
    reports = ingest(settings=active)
    by_source = {report.source: report for report in reports}
    assert by_source["nvd"].status == "disabled"
    assert by_source["nvd"].new == 0
    assert by_source["nvd"].unchanged == 0
    assert by_source["osv"].status == "ok"
    assert by_source["kev"].status == "ok"
    assert by_source["osv"].unchanged > 0
