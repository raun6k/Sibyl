"""Prioritiser.

The score is `scoring.priority_score`. The fast lane writes a rationale
from those components only for needs-human cases and the top 10 ranked
cases. Every other case gets a deterministic rationale built from the
score factors and marked as deterministic. The model cannot change the
score. A model that names a different number is ignored.

An accepted not-affected text case that the Critic tied to another finding
(append-field under multer) is closed. It is not in the needs-human queue.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Literal

from pydantic import BaseModel

from sibyl.agents.critic import CaseView, CriticResult
from sibyl.agents.prompts import load_prompt
from sibyl.config import Settings
from sibyl.llm.client import MAX_IN_FLIGHT
from sibyl.scoring import branch, priority_score

Placement = Literal["ranked", "closed", "needs_human", "recheck"]
RationaleSource = Literal["model", "deterministic", "unavailable"]


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
    rationale_source: RationaleSource = "deterministic"
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
    write_rationale: bool = False,
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
    rationale, flagged, source = _rationale(
        scored.score, scored.components, confidence, llm, write=write_rationale
    )
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
        rationale_source=source,
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


def deterministic_rationale(score: float, components: dict[str, float], confidence: float) -> str:
    factors = ", ".join(f"{name}={value}" for name, value in components.items())
    return (
        f"Deterministic rationale from the score factors: score {score}, "
        f"confidence {confidence}, {factors}."
    )


def model_rationale_targets(placements: list[PlacementResult], *, ranked_limit: int = 10) -> list[PlacementResult]:
    """Needs-human cases, plus the highest-scored ranked cases, up to `ranked_limit`."""
    ranked = [placed for placed in placements if placed.placement == "ranked"]
    ranked.sort(key=lambda placed: (-placed.score, placed.case_id))
    chosen = list(ranked[:ranked_limit])
    seen = {placed.case_id for placed in chosen}
    for placed in placements:
        if placed.placement == "needs_human" and placed.case_id not in seen:
            chosen.append(placed)
            seen.add(placed.case_id)
    return chosen


def write_model_rationales(
    placements: list[PlacementResult],
    llm: object | None,
    *,
    ranked_limit: int = 10,
    allow: Callable[[], bool] | None = None,
) -> None:
    """Fill model rationales for the selected cases. The rest stay deterministic.

    `allow` is checked before each new call. When it returns false, calls
    already running finish and the rest keep the deterministic rationale.
    At most four calls run at once.
    """
    targets = model_rationale_targets(placements, ranked_limit=ranked_limit)
    if llm is None:
        for placed in targets:
            placed.rationale = "unavailable"
            placed.flagged = True
            placed.rationale_source = "unavailable"
        return
    pending = list(targets)

    def _write(placed: PlacementResult) -> None:
        text, flagged, source = _rationale(placed.score, placed.components, placed.confidence, llm, write=True)
        placed.rationale = text
        placed.flagged = flagged
        placed.rationale_source = source

    with ThreadPoolExecutor(max_workers=MAX_IN_FLIGHT) as pool:
        inflight: dict = {}
        while pending or inflight:
            while pending and len(inflight) < MAX_IN_FLIGHT and (allow is None or allow()):
                placed = pending.pop(0)
                inflight[pool.submit(_write, placed)] = placed
            if not inflight:
                break
            done, _ = wait(set(inflight), return_when=FIRST_COMPLETED)
            for future in done:
                inflight.pop(future)
                future.result()


def _rationale(
    score: float,
    components: dict[str, float],
    confidence: float,
    llm: object | None,
    *,
    write: bool,
) -> tuple[str, bool, RationaleSource]:
    if not write:
        return deterministic_rationale(score, components, confidence), False, "deterministic"
    facts = {"score": score, "confidence": confidence, "components": components}
    if llm is None:
        return "unavailable", True, "unavailable"
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
        return "unavailable", True, "unavailable"
    return written.output.rationale, False, "model"


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
