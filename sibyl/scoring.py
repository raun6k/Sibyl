"""Confidence and priority.

Both numbers are code. A model may describe the factors; it does not change
the number. Weights come from `Settings`.

Confidence starts at 1.0 and is multiplied by the source trust weight, by
0.6 when the verdict rests on LLM text, by 0.7 for each unresolved blocking
conflict, and by 0.8 when a relevant source was degraded.

Branch edges, compared after rounding the confidence to 4 decimal places:

- `>= 0.8` is ranked
- `>= 0.5` and `< 0.8` is the middle band; a score `>= high_priority_min`
  (40, the exploited term alone) asks the Critic for one more check
- a middle-band score below that threshold is ranked
- `< 0.5`, or any unresolved blocking conflict, needs a human
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from sibyl.config import Settings
from sibyl.engines.trust import current_table

Branch = Literal["ranked", "recheck", "needs_human"]
RANKED_MIN = 0.8
RECHECK_MIN = 0.5


class Factor(BaseModel):
    name: str
    value: float
    note: str = ""


class ConfidenceResult(BaseModel):
    value: float
    factors: list[Factor] = Field(default_factory=list)


class PriorityResult(BaseModel):
    score: float
    components: dict[str, float]
    inputs: dict[str, float]
    factors: list[Factor] = Field(default_factory=list)


def trust_weight(
    source: str,
    settings: Settings | None = None,
    *,
    field: str = "affected_ranges",
    ecosystem: str = "*",
) -> float:
    """H-MEM weight for this source, or the data.md default when it is down."""
    bound = current_table()
    if bound is not None:
        return bound.weight(source, field, ecosystem)
    table = _settings(settings).trust_weights
    key = source.strip().lower()
    if key in table:
        return table[key]
    return table.get("llm-extracted", 0.5)


def confidence(
    *,
    trust: float,
    llm_text: bool = False,
    blocking_unresolved: int = 0,
    degraded: bool = False,
    settings: Settings | None = None,
) -> ConfidenceResult:
    """Explainable confidence in `[0, 1]`, rounded to 4 decimal places."""
    active = _settings(settings)
    factors = [Factor(name="base", value=1.0, note="structured range starts at 1")]
    value = 1.0
    value *= trust
    factors.append(Factor(name="source_trust", value=trust, note="trust weight for the field"))
    if llm_text:
        value *= active.confidence_llm_factor
        factors.append(
            Factor(name="llm_text", value=active.confidence_llm_factor, note="verdict uses extracted text")
        )
    unresolved = max(blocking_unresolved, 0)
    for _ in range(unresolved):
        value *= active.confidence_blocking_factor
        factors.append(
            Factor(
                name="blocking_conflict",
                value=active.confidence_blocking_factor,
                note="blocking conflict not resolved by a rule",
            )
        )
    if degraded:
        value *= active.confidence_degraded_factor
        factors.append(
            Factor(
                name="degraded_source",
                value=active.confidence_degraded_factor,
                note="a relevant source was degraded or missing",
            )
        )
    bound = current_table()
    if bound is not None and bound.unavailable:
        factors.append(
            Factor(
                name="hmem_unavailable",
                value=1.0,
                note="H-MEM is unavailable; trust is the data.md default",
            )
        )
    return ConfidenceResult(value=_round(value), factors=factors)


# Severity authority from data.md, then the two sources that still carry a
# base score when the CNA, CISA-ADP, and NVD primary are silent.
_CVSS_SOURCES = ("cna", "cisa-adp", "nvd:primary", "ghsa", "osv")


def pick_cvss(rows: list[dict]) -> tuple[float, str, str]:
    """Base score, source, and CVSS version for one vulnerability.

    Sources are tried in field-authority order. Within a source, a 3.x
    score is used ahead of 4.0. A missing or non-numeric score is skipped.
    """
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        source = str(row.get("source") or "").strip().lower()
        if not source:
            continue
        grouped.setdefault(source, []).append(row)
    for source in _CVSS_SOURCES:
        candidates = [(source, list(grouped.get(source) or []))]
        if source == "nvd:primary":
            candidates.append(("nvd", list(grouped.get("nvd") or [])))
        for label, pool in candidates:
            chosen = _choose_cvss(pool)
            if chosen is not None:
                score, version = chosen
                return score, label, version
    return 0.0, "", ""


def _choose_cvss(rows: list[dict]) -> tuple[float, str] | None:
    parsed: list[tuple[str, float]] = []
    for row in rows:
        score = _numeric(row.get("score"))
        if score is None or score <= 0:
            continue
        parsed.append((str(row.get("version") or "").strip(), score))
    if not parsed:
        return None
    threes = [item for item in parsed if item[0].startswith("3")]
    fours = [item for item in parsed if item[0].startswith("4")]
    pool = threes or fours or parsed
    version, score = max(pool, key=lambda item: (item[0], item[1]))
    return score, version


def _numeric(value: object) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def priority_score(
    *,
    exploited: bool,
    epss_percentile: float,
    cvss: float,
    internet_facing: bool,
    criticality: float,
    settings: Settings | None = None,
) -> PriorityResult:
    """Weighted score. `components` are the points each term contributed."""
    active = _settings(settings)
    epss = _clamp(epss_percentile, 0.0, 1.0)
    severity = _clamp(cvss, 0.0, 10.0) / 10.0
    exposure = 1.0 if internet_facing else 0.0
    crit = _clamp(criticality, 0.0, 1.0)
    exploited_bit = 1.0 if exploited else 0.0
    inputs = {
        "exploited": exploited_bit,
        "epss": epss,
        "severity": severity,
        "exposure": exposure,
        "criticality": crit,
    }
    raw = {
        "exploited": active.weight_exploited * exploited_bit,
        "epss": active.weight_epss * epss,
        "severity": active.weight_severity * severity,
        "exposure": active.weight_exposure * exposure,
        "criticality": active.weight_criticality * crit,
    }
    components = {name: _round(points) for name, points in raw.items()}
    factors = [
        Factor(name=name, value=points, note="weighted points") for name, points in components.items()
    ]
    return PriorityResult(
        score=_round(sum(components.values())),
        components=components,
        inputs={name: _round(value) for name, value in inputs.items()},
        factors=factors,
    )


def branch(
    confidence_value: float,
    score: float,
    *,
    unresolved_blocking: bool = False,
    settings: Settings | None = None,
) -> Branch:
    """Rank, ask the Critic once more, or send the case to a human."""
    active = _settings(settings)
    value = _round(confidence_value)
    if unresolved_blocking or value < RECHECK_MIN:
        return "needs_human"
    if value >= RANKED_MIN:
        return "ranked"
    if score >= active.high_priority_min:
        return "recheck"
    return "ranked"


def _settings(settings: Settings | None) -> Settings:
    return settings if settings is not None else Settings()


def _clamp(value: float, low: float, high: float) -> float:
    return min(max(value, low), high)


def _round(value: float) -> float:
    return round(value, 4)
