"""Hand-checked fixture verdicts, plus a constructed conflict and withdrawal."""

import pytest

from sibyl.agents.matcher import load_candidates, match
from sibyl.config import load_settings

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


@pytest.mark.live
def test_hand_checked_fixture_pairs():
    loaded = load_candidates(load_settings())
    assert loaded.truncated is False
    for service in ("checkout-api", "internal-admin", "merchant-portal", "reporting-worker"):
        assert f"WHERE service_id = '{service}'" in loaded.statement
    assert "version =" not in loaded.statement.lower()
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


@pytest.mark.live
def test_nvd_disagreement_at_the_installed_version_is_informational():
    loaded = load_candidates(load_settings())
    outcome = match(loaded.rows)
    validator = [
        verdict
        for verdict in outcome.verdicts
        if verdict.source == "combined"
        and verdict.service_id == "internal-admin"
        and verdict.package == "validator"
        and verdict.version == "13.7.0"
        and verdict.vuln_id == "CVE-2025-56200"
    ]
    assert len(validator) == 1
    assert validator[0].verdict == "affected"
    validator_conflicts = [row for row in outcome.conflicts if row.case_id == validator[0].case_id]
    assert len(validator_conflicts) == 1
    assert validator_conflicts[0].severity == "informational"
    assert validator_conflicts[0].values_by_source["osv"] == "affected"
    assert validator_conflicts[0].values_by_source["nvd"] == "not_affected"
    axios = [
        verdict
        for verdict in outcome.verdicts
        if verdict.source == "combined"
        and verdict.package == "axios"
        and verdict.vuln_id == "CVE-2023-45857"
    ]
    assert {verdict.service_id for verdict in axios} >= {"internal-admin", "merchant-portal"}
    assert all(verdict.verdict == "affected" for verdict in axios)
    for verdict in axios:
        conflict = next(row for row in outcome.conflicts if row.case_id == verdict.case_id)
        assert conflict.severity == "informational"
        assert conflict.values_by_source["osv"] == "affected"
        assert conflict.values_by_source["nvd"] == "not_affected"


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


def test_cna_silence_below_every_branch_is_informational():
    """django 4.2.3: the CNA lists only later branches and defaultStatus is unaffected."""
    rows = [
        _named("osv", "django", "4.2.3", "pypi", introduced="0", fixed="4.2.16", vuln="CVE-2024-1"),
        _named("cve_org", "django", "4.2.3", "pypi", introduced="5.2", fixed="5.2.18", vuln="CVE-2024-1", range_type="CNA"),
        _named("cve_org", "django", "4.2.3", "pypi", introduced="6.0", fixed="6.0.9", vuln="CVE-2024-1", range_type="CNA"),
        _named(
            "cve_org",
            "django",
            "4.2.3",
            "pypi",
            introduced="",
            fixed="",
            vuln="CVE-2024-1",
            range_type="CNA_DEFAULT",
            raw_range="default_status=unaffected",
        ),
    ]
    outcome = match(rows)
    conflict = next(item for item in outcome.conflicts if item.case_id.startswith("case:"))
    assert conflict.severity == "informational"
    assert conflict.field == "cna_branch"
    assert conflict.values_by_source["cna"] == "not_affected"
    assert conflict.values_by_source["osv"] == "affected"


def test_explicit_cna_unaffected_entry_still_blocks():
    rows = [
        _named("osv", "django", "4.2.3", "pypi", introduced="0", fixed="4.2.16", vuln="CVE-2024-1"),
        _named("cve_org", "django", "4.2.3", "pypi", introduced="4.2", fixed="4.2.4", vuln="CVE-2024-1", range_type="CNA_UNAFFECTED"),
        _named(
            "cve_org",
            "django",
            "4.2.3",
            "pypi",
            introduced="",
            fixed="",
            vuln="CVE-2024-1",
            range_type="CNA_DEFAULT",
            raw_range="default_status=unaffected",
        ),
    ]
    outcome = match(rows)
    conflict = outcome.conflicts[0]
    assert conflict.severity == "blocking"
    assert conflict.values_by_source["cna"] == "not_affected"


def _named(source, package, version, ecosystem, **extra) -> dict[str, str]:
    vuln = extra.pop("vuln")
    return {
        "service_id": "checkout-api",
        "purl": f"pkg:{ecosystem}/{package}@{version}",
        "package": package,
        "version": version,
        "ecosystem": ecosystem,
        "source": source,
        "record_status": "active",
        "record_id": f"{source}:{vuln}",
        "vuln_id": vuln,
        "cve_id": vuln,
        "introduced": extra.pop("introduced", ""),
        "fixed": extra.pop("fixed", ""),
        "last_affected": extra.pop("last_affected", ""),
        "raw_range": extra.pop("raw_range", ""),
        "range_type": extra.pop("range_type", "ECOSYSTEM"),
    }


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
