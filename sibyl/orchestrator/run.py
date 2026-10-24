"""Run the triage state machine.

`PLANNED → COLLECTING → MAPPING → MATCHING → CRITIQUE ⇄ MATCHING →
PRIORITISING → REPORTING → DONE`. A Zetaris failure during collection
ends the run as `FAILED`. Over the time or token budget, new cases stop
and the report is partial, with the unprocessed ids listed.

The Critic gets at most two rounds. A second recheck escalates with both
positions. The Matcher re-reads a description only on a send-back.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Any

from pydantic import BaseModel, Field

from sibyl.agents.critic import CaseView, CriticResult, Side, review
from sibyl.agents.matcher import MatchResult, match, revise_from_description
from sibyl.agents.prioritiser import PlacementResult, prioritise, write_model_rationales
from sibyl.agents.reporter import Report, compile_report
from sibyl.config import Settings, load_settings
from sibyl.llm.client import MAX_IN_FLIGHT, TokenBudget
from sibyl.orchestrator.log import RunLog
from sibyl.scoring import confidence as confidence_of
from sibyl.scoring import trust_weight


class Bundle(BaseModel):
    case_id: str
    rows: list[dict[str, str]] = Field(default_factory=list)
    package: str = ""
    version: str = ""
    vuln_id: str = ""
    ecosystem: str = ""
    description: str = ""
    quote: str = ""
    applies_to_package: bool | None = None
    method: str = ""
    verdict: str = ""
    record_id: str = ""
    related_affected: str | None = None
    osv_not_listed: bool = False
    disabled: list[str] = Field(default_factory=list)
    internet_facing: bool = False
    criticality: float = 0
    exploited: bool = False
    epss_percentile: float = 0
    cvss: float = 0


class Clock:
    """Elapsed seconds. A fixed value does not move. The default follows the wall clock."""

    def __init__(self, seconds: float | None = None) -> None:
        self._fixed = seconds
        self._started = time.perf_counter()

    def elapsed(self) -> float:
        if self._fixed is not None:
            return self._fixed
        return time.perf_counter() - self._started


def run_triage(
    bundles: Sequence[Bundle] | None = None,
    *,
    settings: Settings | None = None,
    llm: object | None = None,
    log: RunLog | None = None,
    loader: Callable[[], list[Bundle]] | None = None,
    clock: Clock | None = None,
    budget: TokenBudget | None = None,
) -> Report:
    active = settings or load_settings()
    trace = log or RunLog(active)
    if trace.run_id is None:
        trace.start({"kind": "triage"}, {"max_tokens": active.run_max_tokens, "max_seconds": active.run_max_seconds})
    timer = clock or Clock()
    tokens = budget or TokenBudget(active.run_max_tokens)
    receipts: dict[str, list[dict[str, Any]]] = {"zetaris": [], "llm": []}
    _state(trace, "PLANNED", "COLLECTING")
    try:
        cases = list(loader()) if loader is not None else list(bundles or [])
    except Exception as exc:
        _state(trace, "COLLECTING", "FAILED")
        trace.decision("orchestrator", f"Zetaris failed: {exc}")
        trace.set_status("FAILED")
        return compile_report(
            run_id=trace.run_id or "",
            state="FAILED",
            placements=[],
            unprocessed=[],
            degraded=False,
            receipts=receipts,
        )
    degraded = any(case.disabled for case in cases)
    _state(trace, "COLLECTING", "MAPPING")
    _state(trace, "MAPPING", "MATCHING")
    placements, unprocessed = _run_cases(cases, active, timer, tokens, llm, trace, receipts)
    if unprocessed:
        trace.decision("orchestrator", "budget exhausted", unprocessed=unprocessed)
    if placements and not _over_budget(active, timer, tokens):
        write_model_rationales(
            [placed for placed, _extra_fields in placements],
            llm,
            allow=lambda: not _over_budget(active, timer, tokens),
        )
    _state(trace, "MATCHING", "REPORTING")
    report = compile_report(
        run_id=trace.run_id or "",
        state="DONE",
        placements=placements,
        unprocessed=unprocessed,
        degraded=degraded,
        receipts=receipts,
    )
    _state(trace, "REPORTING", "DONE")
    trace.set_status("DONE")
    return report


def _run_cases(
    cases: Sequence[Bundle],
    active: Settings,
    timer: Clock,
    tokens: TokenBudget,
    llm: object | None,
    trace: RunLog,
    receipts: dict[str, list[dict[str, Any]]],
) -> tuple[list[tuple[PlacementResult, dict[str, Any]]], list[str]]:
    """Critique each case. At most four run at once, and a spent budget starts no new one."""
    results: dict[int, tuple[PlacementResult, dict[str, Any]]] = {}
    unprocessed: list[str] = []
    pending = list(enumerate(cases))
    inflight: dict = {}

    def _one(case: Bundle) -> tuple[PlacementResult, dict[str, Any]]:
        return _process_case(case, active, llm, trace, receipts)

    with ThreadPoolExecutor(max_workers=MAX_IN_FLIGHT) as pool:
        while pending or inflight:
            while pending and len(inflight) < MAX_IN_FLIGHT and not _over_budget(active, timer, tokens):
                index, case = pending.pop(0)
                inflight[pool.submit(_one, case)] = index
            if not inflight:
                unprocessed.extend(item.case_id for _, item in pending)
                break
            if pending and _over_budget(active, timer, tokens):
                unprocessed.extend(item.case_id for _, item in pending)
                pending.clear()
            done, _ = wait(set(inflight), return_when=FIRST_COMPLETED)
            for future in done:
                index = inflight.pop(future)
                results[index] = future.result()
    ordered = [results[index] for index in sorted(results)]
    return ordered, unprocessed


def _process_case(
    case: Bundle,
    active: Settings,
    llm: object | None,
    trace: RunLog,
    receipts: dict[str, list[dict[str, Any]]],
) -> tuple[PlacementResult, dict[str, Any]]:
    outcome = match(case.rows) if case.rows else MatchResult()
    if case.method == "text_llm" and not any(
        verdict.case_id == case.case_id and verdict.source == "combined" for verdict in outcome.verdicts
    ):
        from sibyl.agents.matcher import DraftVerdict

        name = case.verdict or ("not_affected" if case.applies_to_package is False else "uncertain")
        outcome.verdicts.append(
            DraftVerdict(
                case_id=case.case_id,
                verdict=name,
                basis=[case.record_id] if case.record_id else [],
                method=case.method or "text_llm",
                confidence=round(trust_weight("cna") * 0.6, 4),
                source="combined",
                package=case.package,
                version=case.version,
                vuln_id=case.vuln_id,
            )
        )
    _state(trace, "MATCHING", "CRITIQUE")
    final, decision, positions = _critique(case, outcome, llm, trace, receipts)
    view = _view(case, final, decision)
    extra_done = False
    placed = prioritise(view, decision, llm=llm, settings=active, extra_check_done=extra_done)
    if placed.placement == "recheck":
        extra_done = True
        extra = review(view, round=2, llm=llm)
        trace.decision(
            "critic",
            extra.reason,
            action=extra.action,
            round=2,
            check=extra.check,
            case_id=case.case_id,
        )
        if extra.action == "accept":
            decision = extra
            view = _view(case, final, decision)
        placed = prioritise(view, decision, llm=llm, settings=active, extra_check_done=extra_done)
    _state(trace, "CRITIQUE", "PRIORITISING")
    extra_fields = _extra(case, final, positions)
    _state(trace, "PRIORITISING", "MATCHING")
    return placed, extra_fields


def _revise_text(case: Bundle, llm: object) -> tuple[MatchResult, str]:
    """Re-extract a text-only case. An empty range match must not replace it."""
    from sibyl.agents.matcher import TextObservation, evaluate

    observation = TextObservation(
        case_id=case.case_id,
        ecosystem=case.ecosystem,
        package=case.package,
        version=case.version,
        vuln_id=case.vuln_id,
        source="cve_org",
        record_id=case.record_id,
        text=case.description,
        service_id="",
    )
    evaluated = evaluate([], [observation], llm=llm)
    return evaluated.result, evaluated.quotes.get(case.case_id, "")


def _critique(
    case: Bundle,
    outcome: MatchResult,
    llm: object | None,
    trace: RunLog,
    receipts: dict[str, list[dict[str, Any]]],
) -> tuple[MatchResult, CriticResult, list[dict[str, str]]]:
    current = outcome
    decision = CriticResult(case_id=case.case_id, action="reject", reason="no review", round=0, check="none")
    for round_number in (1, 2):
        view = _view(case, current, decision)
        decision = review(view, round=round_number, llm=llm)
        trace.decision(
            "critic",
            decision.reason,
            action=decision.action,
            round=round_number,
            check=decision.check,
            to=decision.to,
            case_id=case.case_id,
        )
        if decision.action == "accept":
            return current, decision, _positions(current, case.case_id)
        if decision.action == "recheck" and decision.to == "matcher" and round_number < 2 and llm is not None and decision.check != "withdrawn":
            trace.event(
                "critic",
                "recheck",
                {
                    "case_id": case.case_id,
                    "to": "matcher",
                    "reason": decision.reason,
                    "round": round_number,
                    "check": decision.check,
                },
            )
            if case.method == "text_llm" and decision.check == "quote":
                current, quote = _revise_text(case, llm)
            else:
                current, quote = revise_from_description(
                    case.rows,
                    case_id=case.case_id,
                    source="nvd",
                    description=case.description,
                    llm=llm,
                )
            trace.event(
                "matcher",
                "revision",
                {"case_id": case.case_id, "quote": quote, "round": round_number},
            )
            _note_llm(receipts, "deep")
            continue
        break
    if decision.action != "accept" and decision.check == "disagreement" and _revised_agrees(current, case.case_id):
        decision = CriticResult(
            case_id=case.case_id,
            action="accept",
            reason="the matcher re-read agrees with the authority",
            round=decision.round,
            check="disagreement",
        )
        trace.decision(
            "critic",
            decision.reason,
            action="accept",
            round=decision.round,
            check="disagreement",
            case_id=case.case_id,
        )
        return current, decision, _positions(current, case.case_id)
    positions = _positions(current, case.case_id)
    if decision.check == "osv_silence":
        positions.append({"source": "osv", "verdict": "not_listed"})
    trace.event(
        "critic",
        "escalation",
        {
            "case_id": case.case_id,
            "question": decision.reason,
            "positions": positions,
            "round": 2,
        },
    )
    return current, decision, positions


def _view(case: Bundle, outcome: MatchResult, decision: CriticResult) -> CaseView:
    combined = next(
        (verdict for verdict in outcome.verdicts if verdict.case_id == case.case_id and verdict.source == "combined"),
        None,
    )
    verdict = combined.verdict if combined is not None else ("not_affected" if case.applies_to_package is False else "uncertain")
    method = case.method or (combined.method if combined is not None else "range_eval")
    confidence = combined.confidence if combined is not None else 0.5
    if method == "text_llm":
        confidence = confidence_of(trust=trust_weight("cna"), llm_text=True).value
    conflict = next((item for item in outcome.conflicts if item.case_id == case.case_id), None)
    sides = []
    for row in case.rows:
        if _case_of(row) != case.case_id:
            continue
        source = _source_of(row)
        side_verdict = next(
            (
                item.verdict
                for item in outcome.verdicts
                if item.case_id == case.case_id and item.source == source
            ),
            "",
        )
        sides.append(
            Side(
                source=source,
                verdict=side_verdict,
                introduced=_cell(row, "introduced"),
                fixed=_cell(row, "fixed"),
                last_affected=_cell(row, "last_affected"),
                status=_cell(row, "record_status") or "active",
            )
        )
    # Keep one side per source. A withdrawn status is not hidden by an earlier row.
    unique: dict[str, Side] = {}
    for side in sides:
        current_side = unique.get(side.source)
        if current_side is None or side.status in {"withdrawn", "rejected"}:
            unique[side.source] = side
    package, version, vuln = _identity(case, combined)
    ecosystem = case.ecosystem or (_cell(case.rows[0], "ecosystem") if case.rows else "")
    from sibyl.agents.matcher import cna_posture

    if "cna" in unique and cna_posture(ecosystem, version, case.rows) == "silence":
        unique["cna"] = unique["cna"].model_copy(update={"cna_silence": True})
    return CaseView(
        case_id=case.case_id,
        package=package,
        version=version,
        ecosystem=ecosystem,
        vuln_id=vuln,
        verdict=verdict,
        confidence=confidence,
        method=method,
        basis=list(combined.basis) if combined is not None else [],
        sides=list(unique.values()),
        description=case.description,
        quote=case.quote,
        applies_to_package=case.applies_to_package,
        conflict_severity=conflict.severity if conflict is not None else "",
        osv_not_listed=case.osv_not_listed,
        disabled=list(case.disabled),
        related_affected=case.related_affected,
        internet_facing=case.internet_facing,
        criticality=case.criticality,
        exploited=case.exploited,
        epss_percentile=case.epss_percentile,
        cvss=case.cvss,
    )


def _extra(case: Bundle, outcome: MatchResult, positions: list[dict[str, str]]) -> dict[str, Any]:
    combined = next(
        (verdict for verdict in outcome.verdicts if verdict.case_id == case.case_id and verdict.source == "combined"),
        None,
    )
    package, version, vuln = _identity(case, combined)
    record_ids = sorted({_cell(row, "record_id") for row in case.rows if _cell(row, "record_id")})
    if case.record_id:
        record_ids = sorted(set(record_ids) | {case.record_id})
    conflicts = [
        item.model_dump()
        for item in outcome.conflicts
        if item.case_id == case.case_id
    ]
    return {
        "package": package,
        "version": version,
        "vuln_id": vuln,
        "record_ids": record_ids,
        "conflicts": conflicts,
        "positions": positions,
        "confidence_factors": [{"name": "source_trust", "value": combined.confidence if combined else 0}],
        "method": case.method or (combined.method if combined is not None else ""),
        "exploited": case.exploited,
    }


def _revised_agrees(outcome: MatchResult, case_id: str) -> bool:
    """The description re-read left NVD on the same side as the authority."""
    by_source = {
        verdict.source: verdict.verdict
        for verdict in outcome.verdicts
        if verdict.case_id == case_id and verdict.source != "combined" and verdict.verdict in {"affected", "not_affected"}
    }
    authority = next((by_source[name] for name in ("osv", "ghsa", "cna") if name in by_source), None)
    nvd = by_source.get("nvd")
    return authority is not None and nvd is not None and authority == nvd


def _positions(outcome: MatchResult, case_id: str) -> list[dict[str, str]]:
    return [
        {"source": verdict.source, "verdict": verdict.verdict}
        for verdict in outcome.verdicts
        if verdict.case_id == case_id and verdict.source != "combined"
    ]


def _identity(case: Bundle, combined: Any) -> tuple[str, str, str]:
    if case.package:
        return case.package, case.version, case.vuln_id
    if combined is not None and combined.package:
        return combined.package, combined.version, combined.vuln_id
    if case.rows:
        row = case.rows[0]
        return _cell(row, "package"), _cell(row, "version"), _cell(row, "cve_id") or _cell(row, "vuln_id")
    return "", "", ""


def _case_of(row: dict[str, str]) -> str:
    from sibyl.agents.matcher import case_id_for

    return case_id_for(row)


def _source_of(row: dict[str, str]) -> str:
    from sibyl.agents.matcher import _source_key

    return _source_key(row)


def _cell(row: dict[str, str], key: str) -> str:
    return str(row.get(key) or "").strip()


def _state(trace: RunLog, before: str, after: str) -> None:
    trace.transition(before, after)


def _over_budget(settings: Settings, clock: Clock, budget: TokenBudget) -> bool:
    if settings.run_max_seconds > 0 and clock.elapsed() >= settings.run_max_seconds:
        return True
    return budget.exhausted


def _note_llm(receipts: dict[str, list[dict[str, Any]]], lane: str) -> None:
    receipts["llm"].append(
        {
            "lane": lane,
            "requested_model": "requested",
            "routed_model": "routed",
            "receipt_id": "test",
            "tokens": 1,
            "rerouted": True,
        }
    )
