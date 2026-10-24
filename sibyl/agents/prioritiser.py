"""Prioritiser.

The score is `scoring.priority_score`. The fast lane writes the rationale
from those components. It cannot change the score. A model that names a
different number is ignored.

An accepted not-affected text case that the Critic tied to another finding
(append-field under multer) is closed. It is not in the needs-human queue.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel

from sibyl.agents.critic import CaseView, CriticResult
from sibyl.agents.prompts import load_prompt
from sibyl.config import Settings
from sibyl.scoring import branch, priority_score

Placement = Literal["ranked", "closed", "needs_human", "recheck"]


class Rationale(BaseModel):
    rationale: str


class PlacementResult(BaseModel):
    case_id: str
    verdict: str
    score: float
    components: dict[str, float]
    confidence: float
    placement: Placement
    rationale: str
    question: str = ""
    accepted_under: str | None = None
    flagged: bool = False


def prioritise(
    view: CaseView,
    decision: CriticResult,
    *,
    llm: object | None = None,
    settings: Settings | None = None,
    extra_check_done: bool = False,
) -> PlacementResult:
    scored = priority_score(
        exploited=view.exploited,
        epss_percentile=view.epss_percentile,
        cvss=view.cvss,
        internet_facing=view.internet_facing,
        criticality=view.criticality,
        settings=settings,
    )
    confidence = view.confidence
    if decision.degraded:
        active = settings or Settings()
        confidence = round(confidence * active.confidence_degraded_factor, 4)
    where = _placement(view, decision, scored.score, confidence, extra_check_done, settings)
    rationale, flagged = _rationale(scored.score, scored.components, confidence, llm)
    question = ""
    if where == "needs_human":
        question = _question(view, decision)
    return PlacementResult(
        case_id=view.case_id,
        verdict=view.verdict,
        score=scored.score,
        components=scored.components,
        confidence=confidence,
        placement=where,
        rationale=rationale,
        question=question,
        accepted_under=decision.accepted_under,
        flagged=flagged,
    )


def _placement(
    view: CaseView,
    decision: CriticResult,
    score: float,
    confidence: float,
    extra_check_done: bool,
    settings: Settings | None,
) -> Placement:
    if decision.action == "accept" and view.verdict == "not_affected" and decision.accepted_under:
        return "closed"
    unresolved = decision.action != "accept" or view.conflict_severity == "blocking"
    if decision.action == "accept" and not unresolved:
        chosen = branch(confidence, score, unresolved_blocking=False, settings=settings)
        if chosen == "recheck" and extra_check_done:
            return "ranked"
        return chosen
    return "needs_human"


def _rationale(score: float, components: dict[str, float], confidence: float, llm: object | None) -> tuple[str, bool]:
    facts = {"score": score, "confidence": confidence, "components": components}
    if llm is None:
        return "unavailable", True
    try:
        written = llm.complete(
            "fast",
            [
                {"role": "system", "content": load_prompt("prioritiser")},
                {"role": "user", "content": json.dumps(facts)},
            ],
            Rationale,
        )
    except Exception:
        return "unavailable", True
    return written.output.rationale, False


def _question(view: CaseView, decision: CriticResult) -> str:
    if decision.action != "accept":
        return (
            f"Which source should decide {view.package}@{view.version} ({view.vuln_id})? "
            f"The last critic reason was: {decision.reason}"
        )
    return (
        f"Is {view.package}@{view.version} affected by {view.vuln_id}? "
        f"Confidence is {view.confidence}."
    )
