"""Confidence, priority, and the 0.5 / 0.8 branch edges."""

from sibyl.config import DEFAULT_TRUST, Settings
from sibyl.scoring import RANKED_MIN, RECHECK_MIN, branch, confidence, priority_score, trust_weight


def test_default_trust_matches_the_data_table():
    assert trust_weight("osv") == 0.95
    assert trust_weight("GHSA") == 0.9
    assert trust_weight("cna") == 0.8
    assert trust_weight("cisa-adp") == 0.8
    assert trust_weight("euvd") == 0.75
    assert trust_weight("nvd-cpe") == 0.7
    assert trust_weight("llm-extracted") == 0.5
    assert trust_weight("unknown-source") == DEFAULT_TRUST["llm-extracted"]


def test_confidence_multipliers_and_factors():
    plain = confidence(trust=0.95)
    assert plain.value == 0.95
    assert [factor.name for factor in plain.factors] == ["base", "source_trust"]

    extracted = confidence(trust=0.95, llm_text=True)
    assert extracted.value == 0.57
    assert extracted.factors[-1].name == "llm_text"
    assert extracted.factors[-1].value == 0.6

    blocked = confidence(trust=0.95, blocking_unresolved=1)
    assert blocked.value == 0.665
    degraded = confidence(trust=0.95, degraded=True)
    assert degraded.value == 0.76

    both = confidence(trust=0.95, blocking_unresolved=2, degraded=True)
    assert both.value == round(0.95 * 0.7 * 0.7 * 0.8, 4)
    assert [factor.name for factor in both.factors].count("blocking_conflict") == 2

    stacked = confidence(trust=0.5, llm_text=True, blocking_unresolved=1, degraded=True)
    assert stacked.value == round(0.5 * 0.6 * 0.7 * 0.8, 4)
    assert stacked.value == stacked.factors[0].value * _product(stacked)


def _product(result) -> float:
    value = 1.0
    for factor in result.factors:
        if factor.name == "base":
            continue
        value *= factor.value
    return round(value, 4)


def test_priority_formula_returns_each_component():
    full = priority_score(
        exploited=True,
        epss_percentile=1,
        cvss=10,
        internet_facing=True,
        criticality=1,
    )
    assert full.score == 100
    assert full.components == {
        "exploited": 40,
        "epss": 20,
        "severity": 15,
        "exposure": 15,
        "criticality": 10,
    }
    assert full.score == round(sum(full.components.values()), 4)

    mixed = priority_score(
        exploited=True,
        epss_percentile=0.5,
        cvss=5,
        internet_facing=False,
        criticality=0.5,
    )
    assert mixed.components == {
        "exploited": 40,
        "epss": 10,
        "severity": 7.5,
        "exposure": 0,
        "criticality": 5,
    }
    assert mixed.score == 62.5

    quiet = priority_score(
        exploited=False,
        epss_percentile=0,
        cvss=0,
        internet_facing=False,
        criticality=0,
    )
    assert quiet.score == 0
    assert {factor.name for factor in quiet.factors} == set(quiet.components)


def test_priority_weights_come_from_settings():
    settings = Settings(weight_exploited=10, weight_epss=0, weight_severity=0, weight_exposure=0, weight_criticality=0)
    scored = priority_score(
        exploited=True,
        epss_percentile=1,
        cvss=10,
        internet_facing=True,
        criticality=1,
        settings=settings,
    )
    assert scored.score == 10
    assert scored.components["exploited"] == 10


def test_branch_edges_at_0_8_and_0_5():
    assert RANKED_MIN == 0.8
    assert RECHECK_MIN == 0.5
    high = Settings().high_priority_min

    assert branch(0.8, 0) == "ranked"
    assert branch(1.0, high) == "ranked"
    assert branch(0.8, 100, unresolved_blocking=True) == "needs_human"

    assert branch(0.7999, high) == "recheck"
    assert branch(0.7999, high - 0.0001) == "ranked"
    assert branch(0.5, high) == "recheck"
    assert branch(0.5, 0) == "ranked"

    assert branch(0.4999, 100) == "needs_human"
    assert branch(0.0, high) == "needs_human"
    assert branch(0.9, 0, unresolved_blocking=True) == "needs_human"


def test_branch_uses_the_rounded_confidence():
    assert branch(0.79996, 100) == "ranked"
    assert branch(0.49994, 100) == "needs_human"
