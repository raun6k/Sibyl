"""Boundary checks for univers-backed range evaluation."""

from sibyl.tools.collectors.normalize import cvss3_score
from sibyl.tools.version_eval import is_affected

# ecosystem, version, ranges, expected. The note says why this boundary matters.
CASES = [
    ("pypi", "1.0", [{"introduced": "1.0", "fixed": "1.2.0"}], True, "exactly introduced is affected"),
    ("pypi", "1.2.0", [{"introduced": "1.0", "fixed": "1.2.0"}], False, "exactly fixed is not affected"),
    ("pypi", "1.1", [{"introduced": "1.0", "fixed": "1.2.0"}], True, "between introduced and fixed"),
    ("pypi", "1.2.3", [{"introduced": "0", "last_affected": "1.2.3"}], True, "exactly last_affected is affected"),
    ("pypi", "1.2.4", [{"introduced": "0", "last_affected": "1.2.3"}], False, "the next version after last_affected is not"),
    ("pypi", "1.2.0a1", [{"introduced": "1.0", "fixed": "1.2.0"}], True, "a PyPI pre-release is before the fixed release"),
    ("pypi", "1.2.0", [{"introduced": "1.0", "fixed": "1.2.0"}], False, "the release named by fixed is excluded"),
    ("npm", "1.2.0-rc.1", [{"introduced": "1.0.0", "fixed": "1.2.0"}], True, "an npm pre-release is before 1.2.0"),
    ("npm", "1.2.0", [{"introduced": "1.0.0", "fixed": "1.2.0"}], False, "exactly fixed on npm"),
    ("npm", "1.0.0", [{"introduced": "1.0.0", "fixed": "1.2.0"}], True, "exactly introduced on npm"),
    ("pypi", "4.2.13", [{"introduced": "0", "fixed": "4.2.14"}], True, "introduced 0 has no lower bound"),
    ("pypi", "4.2.14", [{"introduced": "0", "fixed": "4.2.14"}], False, "introduced 0 still excludes fixed"),
    ("npm", "1.0.0", [{"raw_range": ">= 1.0, < 1.2.3"}], True, "GHSA lower bound is inclusive"),
    ("npm", "1.2.2", [{"raw_range": ">= 1.0, < 1.2.3"}], True, "inside a GHSA range"),
    ("npm", "1.2.3", [{"raw_range": ">= 1.0, < 1.2.3"}], False, "GHSA upper bound is exclusive"),
    ("pypi", "1.0", [{"raw_range": ">= 1.0, < 1.2.3"}], True, "the same GHSA string on PyPI, lower bound"),
    ("pypi", "1.2.3", [{"raw_range": ">= 1.0, < 1.2.3"}], False, "the same GHSA string on PyPI, upper bound"),
    ("npm", "1.3.3", [{"raw_range": "<= 1.3.3"}], True, "GHSA <= includes the named version"),
    ("npm", "1.3.4", [{"raw_range": "<= 1.3.3"}], False, "GHSA <= excludes the next version"),
    (
        "pypi",
        "1.5",
        [{"introduced": "1.0", "fixed": "1.2"}, {"introduced": "1.4", "fixed": "1.6"}],
        True,
        "any matching range makes the version affected",
    ),
    (
        "pypi",
        "1.3",
        [{"introduced": "1.0", "fixed": "1.2"}, {"introduced": "1.4", "fixed": "1.6"}],
        False,
        "a version between two ranges is not affected",
    ),
    ("pypi", "1.0", [], None, "no range cannot be decided"),
    ("pypi", "not-a-version", [{"introduced": "1.0", "fixed": "2.0"}], None, "an unparseable version cannot be decided"),
    ("pypi", "1.0", [{"introduced": "nope"}], None, "an unparseable bound cannot be decided"),
    ("pypi", "1.0", [{"range_type": "GIT", "introduced": "abc"}], None, "a GIT range is not a version decision"),
    (
        "pypi",
        "10.0.1",
        [{"introduced": "9.1.0", "last_affected": "9.1.0", "raw_range": "9.1.0"}],
        False,
        "an exact listed version does not match a different version",
    ),
    (
        "pypi",
        "9.1.0",
        [{"introduced": "9.1.0", "last_affected": "9.1.0", "raw_range": "9.1.0"}],
        True,
        "an exact listed version matches that version",
    ),
]


def test_version_boundaries():
    for ecosystem, version, ranges, expected, why in CASES:
        got = is_affected(ecosystem, version, ranges)
        assert got is expected, f"{why}: {ecosystem} {version} -> {got}, expected {expected}"


def test_cvss31_roundup_matches_the_ghsa_score():
    # GHSA-2328-f5f3-gj25 publishes this vector with score 7.4.
    vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
    assert cvss3_score(vector) == 7.4
    assert cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N") is None
