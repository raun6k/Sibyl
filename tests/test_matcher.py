"""Hand-checked fixture verdicts, plus a constructed conflict and withdrawal."""

from sibyl.agents.matcher import load_candidates, match
from sibyl.config import load_settings
from sibyl.tools.zetaris import readonly_statement

# Each note is why this installed version gets that verdict.
HAND_CHECKED = [
    (
        "checkout-api",
        "pyyaml",
        "5.3.1",
        "CVE-2020-14343",
        "affected",
        "OSV says introduced 0 and fixed 5.4, and 5.3.1 is before that fix.",
    ),
    (
        "reporting-worker",
        "pyyaml",
        "6.0.1",
        "CVE-2020-14343",
        "not_affected",
        "The same OSV range is fixed at 5.4, so 6.0.1 is outside it.",
    ),
    (
        "checkout-api",
        "certifi",
        "2023.7.22",
        "CVE-2024-39689",
        "affected",
        "OSV and GHSA both say >= 2021.5.30 and < 2024.7.4, which contains 2023.7.22.",
    ),
    (
        "reporting-worker",
        "certifi",
        "2026.10.19",
        "CVE-2024-39689",
        "not_affected",
        "2026.10.19 is after the shared fixed version 2024.7.4.",
    ),
    (
        "checkout-api",
        "pillow",
        "10.0.1",
        "CVE-2023-4863",
        "not_affected",
        "OSV fixes this at 10.0.1, and the installed version is exactly that fix.",
    ),
    (
        "internal-admin",
        "lodash",
        "4.17.15",
        "CVE-2020-28500",
        "affected",
        "OSV's semver range is introduced 4.0.0 and fixed 4.17.21. The CNA text did not become a range.",
    ),
]


def test_hand_checked_fixture_pairs():
    loaded = load_candidates(load_settings())
    assert loaded.statement == readonly_statement("SELECT * FROM sibyl.v_candidate_matches")
    outcome = match(loaded.rows)
    for service, package, version, vuln, expected, why in HAND_CHECKED:
        found = [
            verdict
            for verdict in outcome.verdicts
            if verdict.source == "combined"
            and verdict.service_id == service
            and verdict.package == package
            and verdict.version == version
            and verdict.vuln_id == vuln
        ]
        assert len(found) == 1, f"{why}: found {len(found)}"
        assert found[0].verdict == expected, f"{why}: got {found[0].verdict}"
        assert found[0].method == "range_eval"


def test_a_source_conflict_is_blocking():
    rows = [
        _row("osv", "1.0.0", introduced="1.0.0", fixed="2.0.0", vuln="CVE-1"),
        _row("ghsa", "1.0.0", introduced="1.5.0", fixed="1.8.0", vuln="CVE-1"),
    ]
    outcome = match(rows)
    combined = next(verdict for verdict in outcome.verdicts if verdict.source == "combined")
    assert combined.verdict == "affected"
    assert len(outcome.conflicts) == 1
    conflict = outcome.conflicts[0]
    assert conflict.field == "affected_ranges"
    assert conflict.severity == "blocking"
    assert conflict.values_by_source["osv"] == "affected"
    assert conflict.values_by_source["ghsa"] == "not_affected"


def test_a_withdrawn_record_never_yields_affected():
    rows = [
        _row(
            "osv",
            "1.2.0",
            introduced="1.0.0",
            fixed="2.0.0",
            vuln="CVE-WITHDRAWN",
            status="withdrawn",
        )
    ]
    outcome = match(rows)
    assert outcome.verdicts
    assert all(verdict.verdict != "affected" for verdict in outcome.verdicts)
    combined = next(verdict for verdict in outcome.verdicts if verdict.source == "combined")
    assert combined.verdict == "not_affected"


def _row(
    source: str,
    version: str,
    *,
    introduced: str,
    fixed: str,
    vuln: str,
    status: str = "active",
) -> dict[str, str]:
    return {
        "service_id": "checkout-api",
        "purl": f"pkg:pypi/widget@{version}",
        "package": "widget",
        "version": version,
        "ecosystem": "pypi",
        "source": source,
        "record_status": status,
        "record_id": f"{source}:{vuln}",
        "vuln_id": vuln,
        "cve_id": vuln,
        "range_type": "ECOSYSTEM",
        "introduced": introduced,
        "fixed": fixed,
        "last_affected": "",
        "raw_range": "",
        "range_index": "0",
    }
