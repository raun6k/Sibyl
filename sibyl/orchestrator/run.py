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
from contextvars import copy_context
from typing import Any

from pydantic import BaseModel, Field

from sibyl.agents.critic import CaseView, CriticResult, Side, review
from sibyl.agents.matcher import MatchResult, match, revise_from_description
from sibyl.agents.prioritiser import PlacementResult, prioritise, write_model_rationales
from sibyl.agents.reporter import Report, compile_report
from sibyl.config import Settings, load_settings
from sibyl.engines.hmem import HmemClient
from sibyl.engines.trust import TrustTable, reset_table
from sibyl.engines.world_model import WorldModelClient
from sibyl.llm.client import MAX_IN_FLIGHT, TokenBudget
from sibyl.orchestrator.log import RunLog
from sibyl.scoring import confidence as confidence_of
from sibyl.scoring import trust_weight
from sibyl.tools.zetaris import run_sql, sql_actor


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
    cvss_source: str = ""
    cvss_version: str = ""
    purl: str = ""
    text_bound: str = ""


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
    hmem: HmemClient | None = None,
    world: WorldModelClient | None = None,
    precollected: bool = False,
) -> Report:
    active = settings or load_settings()
    trace = log or RunLog(active)
    if trace.run_id is None:
        trace.start({"kind": "triage"}, {"max_tokens": active.run_max_tokens, "max_seconds": active.run_max_seconds})
    timer = clock or Clock()
    tokens = budget or TokenBudget(active.run_max_tokens)
    receipts: dict[str, list[dict[str, Any]]] = {"zetaris": [], "llm": []}
    table = TrustTable(hmem, active)
    token = table.bind()
    ingest_report: dict[str, Any] | None = None
    try:
        if world is not None:
            ingest_report = ingest_advisories(active, world)
        if precollected:
            cases = list(bundles or [])
            _state(trace, "MAPPING", "MATCHING")
        else:
            _state(trace, "PLANNED", "COLLECTING")
            try:
                cases = list(loader()) if loader is not None else list(bundles or [])
            except Exception as exc:
                _state(trace, "COLLECTING", "FAILED")
                trace.decision("orchestrator", f"Zetaris failed: {exc}")
                trace.set_status("FAILED")
                failed = compile_report(
                    run_id=trace.run_id or "",
                    state="FAILED",
                    placements=[],
                    unprocessed=[],
                    degraded=False,
                    receipts=receipts,
                )
                failed.ingest = ingest_report
                return failed
            _state(trace, "COLLECTING", "MAPPING")
            _state(trace, "MAPPING", "MATCHING")
        degraded = any(case.disabled for case in cases)
        placements, unprocessed = _run_cases(cases, active, timer, tokens, llm, trace, receipts, hmem)
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
        report.ingest = ingest_report
        if hmem is not None and trace.run_id:
            hmem.summary(
                trace.run_id,
                needs_human=len(report.needs_human),
                ranked=len(report.ranked),
                closed=len(report.closed),
            )
        _state(trace, "REPORTING", "DONE")
        trace.set_status("DONE")
        return report
    finally:
        reset_table(token)


def ingest_advisories(settings: Settings, world: WorldModelClient) -> dict[str, Any]:
    """Re-ingest source records by content hash. Unchanged rows are an empty diff."""
    rows: list[dict[str, str]] = []
    last = ""
    with sql_actor("orchestrator"):
        while True:
            page = f" AND record_id > '{last}'" if last else ""
            loaded = run_sql(
                "SELECT record_id, source, content_hash, retrieved_at FROM evidence.source_records "
                f"WHERE record_id IS NOT NULL{page} ORDER BY record_id",
                settings=settings,
                limit=5000,
            )
            rows.extend(loaded.rows)
            if not loaded.truncated or not loaded.rows:
                break
            nxt = loaded.rows[-1].get("record_id") or ""
            if not nxt or nxt == last:
                break
            last = nxt
    observations = []
    for row in rows:
        record_id = row.get("record_id") or ""
        if not record_id:
            continue
        at = row.get("retrieved_at") or ""
        observations.append(
            {
                "externalId": record_id,
                "title": row.get("content_hash") or record_id,
                "at": at,
                "source": {"kind": row.get("source") or "advisory", "at": at},
            }
        )
    report = world.ingest(observations)
    if not isinstance(report, dict):
        raise RuntimeError("world model ingest did not return an object")
    return report


def _run_cases(
    cases: Sequence[Bundle],
    active: Settings,
    timer: Clock,
    tokens: TokenBudget,
    llm: object | None,
    trace: RunLog,
    receipts: dict[str, list[dict[str, Any]]],
    hmem: HmemClient | None = None,
) -> tuple[list[tuple[PlacementResult, dict[str, Any]]], list[str]]:
    """Critique each case. At most four run at once, and a spent budget starts no new one."""
    results: dict[int, tuple[PlacementResult, dict[str, Any]]] = {}
    unprocessed: list[str] = []
    pending = list(enumerate(cases))
    inflight: dict = {}

    def _one(case: Bundle) -> tuple[PlacementResult, dict[str, Any]]:
        return _process_case(case, active, llm, trace, receipts, hmem)

    with ThreadPoolExecutor(max_workers=MAX_IN_FLIGHT) as pool:
        while pending or inflight:
            while pending and len(inflight) < MAX_IN_FLIGHT and not _over_budget(active, timer, tokens):
                index, case = pending.pop(0)
                ctx = copy_context()
                inflight[pool.submit(ctx.run, _one, case)] = index
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
    hmem: HmemClient | None = None,
) -> tuple[PlacementResult, dict[str, Any]]:
    remembered = hmem.resolution_for(case.case_id) if hmem is not None else None
    if remembered and remembered.get("scope", "this_case") == "this_case":
        return _from_memory(case, remembered, active, trace)
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
    if active.critic_enabled:
        final, decision, positions = _critique(case, outcome, llm, trace, receipts)
    else:
        final, decision, positions = _uncritiqued(case, outcome, trace)
    view = _view(case, final, decision)
    extra_done = not active.critic_enabled
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
    if decision.action == "accept":
        extra_fields["resolution"] = "critic"
    else:
        extra_fields["resolution"] = "unresolved"
    flags = _low_trust_flags(view)
    if flags:
        extra_fields["low_trust_flags"] = flags
    _state(trace, "PRIORITISING", "MATCHING")
    return placed, extra_fields


def _from_memory(
    case: Bundle,
    remembered: dict[str, Any],
    active: Settings,
    trace: RunLog,
) -> tuple[PlacementResult, dict[str, Any]]:
    """A stored human resolution decides the case. It is not sent to the Critic again."""
    from sibyl.agents.matcher import DraftVerdict

    decision_name = str(remembered.get("decision") or "uncertain")
    verdict = decision_name if decision_name in {"affected", "not_affected", "uncertain"} else "not_affected"
    if decision_name == "accept_risk":
        verdict = "not_affected"
    outcome = match(case.rows) if case.rows else MatchResult()
    outcome.verdicts = [
        item
        for item in outcome.verdicts
        if not (item.case_id == case.case_id and item.source == "combined")
    ]
    outcome.verdicts.insert(
        0,
        DraftVerdict(
            case_id=case.case_id,
            verdict=verdict,  # type: ignore[arg-type]
            basis=[case.case_id],
            method="memory",
            confidence=1.0,
            source="combined",
            package=case.package,
            version=case.version,
            vuln_id=case.vuln_id,
        ),
    )
    scored = confidence_of(trust=1.0)
    decision = CriticResult(
        case_id=case.case_id,
        action="accept",
        reason=str(remembered.get("note") or "a human resolution decided this case"),
        round=0,
        check="memory",
    )
    case.method = "memory"
    case.verdict = verdict
    view = _view(case, outcome, decision)
    view.method = "memory"
    view.verdict = verdict
    view.confidence = 1.0
    placed = _remembered_placement(placed, verdict)
    placed.confidence = 1.0
    trace.decision(
        "memory",
        decision.reason,
        case_id=case.case_id,
        resolution="memory",
        action="accept",
        check="memory",
    )
    extra = _extra(case, outcome, _positions(outcome, case))
    extra["method"] = "memory"
    extra["resolution"] = "memory"
    extra["confidence_factors"] = [factor.model_dump() for factor in scored.factors] + [
        {"name": "human_resolution", "value": 1.0, "note": decision.reason},
    ]
    flags = _low_trust_flags(view)
    if flags:
        extra["low_trust_flags"] = flags
    return placed, extra


def _remembered_placement(placed: PlacementResult, verdict: str) -> PlacementResult:
    """A stored decision keeps its verdict. Uncertain still asks a human."""
    if verdict == "affected":
        placed.placement = "ranked"
    elif verdict == "not_affected":
        placed.placement = "closed"
        if not placed.rationale:
            placed.rationale = "a human resolution decided this case"
    else:
        placed.placement = "needs_human"
        if not placed.question:
            placed.question = placed.rationale or "A human left this case uncertain."
    return placed


def _low_trust_flags(view: CaseView) -> list[str]:
    """A lower-trust claim is flagged. It does not replace a higher-trust or human verdict."""
    ceiling = 1.0 if view.method == "memory" else None
    if ceiling is None:
        authority = next((side for side in view.sides if side.verdict == view.verdict), None)
        if authority is None:
            return []
        ceiling = trust_weight(authority.source, field="affected_ranges", ecosystem=view.ecosystem or "*")
    flags: list[str] = []
    for side in view.sides:
        if side.verdict not in {"affected", "not_affected"} or side.verdict == view.verdict:
            continue
        weight = trust_weight(side.source, field="affected_ranges", ecosystem=view.ecosystem or "*")
        if weight < ceiling:
            flags.append(f"{side.source} trust {weight} cannot overturn the verdict")
    return flags


def _from_memory(
    case: Bundle,
    remembered: dict[str, Any],
    active: Settings,
    trace: RunLog,
) -> tuple[PlacementResult, dict[str, Any]]:
    """A stored human resolution decides the case. It is not sent to the Critic again."""
    decision_name = str(remembered.get("decision") or "uncertain")
    verdict = decision_name if decision_name in {"affected", "not_affected", "uncertain"} else "not_affected"
    if decision_name == "accept_risk":
        verdict = "not_affected"
    from sibyl.agents.matcher import DraftVerdict, MatchResult

    outcome = match(case.rows) if case.rows else MatchResult()
    outcome.verdicts.append(
        DraftVerdict(
            case_id=case.case_id,
            verdict=verdict,  # type: ignore[arg-type]
            basis=[str(remembered.get("case_id") or case.case_id)],
            method="memory",
            confidence=1.0,
            source="combined",
            package=case.package,
            version=case.version,
            vuln_id=case.vuln_id,
        )
    )
    scored = confidence_of(trust=1.0)
    decision = CriticResult(
        case_id=case.case_id,
        action="accept",
        reason=str(remembered.get("note") or "a human resolution decided this case"),
        round=0,
        check="memory",
    )
    case.method = "memory"
    case.verdict = verdict
    view = _view(case, outcome, decision)
    view.method = "memory"
    view.verdict = verdict
    view.confidence = 1.0
    placed = prioritise(view, decision, llm=None, settings=active)
    placed = _remembered_placement(placed, verdict)
    placed.confidence = 1.0
    trace.decision(
        "memory",
        decision.reason,
        case_id=case.case_id,
        resolution="memory",
        action="accept",
        check="memory",
    )
    extra = _extra(case, outcome, _positions(outcome, case))
    extra["method"] = "memory"
    extra["resolution"] = "memory"
    extra["confidence_factors"] = [factor.model_dump() for factor in scored.factors] + [
        {"name": "human_resolution", "value": 1.0, "note": decision.reason},
    ]
    flags = _low_trust_flags(view)
    if flags:
        extra["low_trust_flags"] = flags
    return placed, extra


def _low_trust_flags(view: CaseView) -> list[str]:
    """A lower-trust source that disagrees is recorded. It does not replace the verdict."""
    holder = trust_weight("human") if view.method == "memory" else None
    flags: list[str] = []
    for side in view.sides:
        if side.verdict not in {"affected", "not_affected"} or side.verdict == view.verdict:
            continue
        weight = trust_weight(side.source, field="affected_ranges", ecosystem=view.ecosystem or "*")
        ceiling = holder if holder is not None else trust_weight("osv", field="affected_ranges", ecosystem=view.ecosystem or "*")
        if weight < ceiling:
            flags.append(f"{side.source} trust {weight} cannot overturn the verdict")
    return flags


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


def _uncritiqued(
    case: Bundle,
    outcome: MatchResult,
    trace: RunLog,
) -> tuple[MatchResult, CriticResult, list[dict[str, str]]]:
    """The critic is off. The Matcher's verdict is accepted as drafted.

    A blocking conflict still goes to needs-human, because the Prioritiser
    places it there; nothing re-reads or resolves it.
    """
    decision = CriticResult(
        case_id=case.case_id,
        action="accept",
        reason="critic disabled",
        round=0,
        check="disabled",
    )
    trace.decision("critic", decision.reason, action="accept", round=0, check="disabled", case_id=case.case_id)
    return outcome, decision, _positions(outcome, case)


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
            return current, decision, _positions(current, case)
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
        return current, decision, _positions(current, case)
    positions = _positions(current, case)
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
        cvss_source=case.cvss_source,
        cvss_version=case.cvss_version,
        purl=case.purl,
        text_bound=case.text_bound,
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
        "confidence_factors": _confidence_factors(case, combined),
        "method": case.method or (combined.method if combined is not None else ""),
        "exploited": case.exploited,
        "ecosystem": case.ecosystem,
        "purl": case.purl,
        "cvss": case.cvss,
        "cvss_source": case.cvss_source,
        "cvss_version": case.cvss_version,
        "epss_percentile": case.epss_percentile,
    }


def _confidence_factors(case: Bundle, combined: Any) -> list[dict[str, Any]]:
    method = case.method or (combined.method if combined is not None else "")
    if method == "memory":
        scored = confidence_of(trust=1.0)
    elif method == "text_llm":
        scored = confidence_of(
            trust=trust_weight("cna", field="affected_ranges", ecosystem=case.ecosystem or "*"),
            llm_text=True,
            degraded=bool(case.disabled),
        )
    else:
        scored = confidence_of(
            trust=trust_weight("osv", field="affected_ranges", ecosystem=case.ecosystem or "*"),
            llm_text=False,
            degraded=bool(case.disabled),
            blocking_unresolved=0,
        )
    return [factor.model_dump() for factor in scored.factors]


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


def _positions(outcome: MatchResult, case: Bundle) -> list[dict[str, str]]:
    """One position per source: verdict, record status, and a version bound.

    A withdrawn GHSA row keeps status `withdrawn`. A CNA "through 3.0.3"
    range keeps that bound, so a needs-human case can show all three.
    """
    status_by_source: dict[str, str] = {}
    bound_by_source: dict[str, str] = {}
    for row in case.rows:
        if _case_of(row) != case.case_id:
            continue
        source = _source_of(row)
        status = _cell(row, "record_status") or "active"
        if source not in status_by_source or status in {"withdrawn", "rejected"}:
            status_by_source[source] = status
        bound = _cell(row, "last_affected") or _cell(row, "fixed")
        if bound and source not in bound_by_source:
            bound_by_source[source] = bound
    positions: list[dict[str, str]] = []
    seen: set[str] = set()
    for verdict in outcome.verdicts:
        if verdict.case_id != case.case_id or verdict.source == "combined" or verdict.source in seen:
            continue
        seen.add(verdict.source)
        item = {
            "source": verdict.source,
            "verdict": verdict.verdict,
            "status": status_by_source.get(verdict.source, "active"),
        }
        bound = bound_by_source.get(verdict.source)
        if bound:
            item["bound"] = bound
        positions.append(item)
    _add_text_position(positions, case)
    if case.osv_not_listed and not any(item.get("source") == "osv" for item in positions):
        positions.append({"source": "osv", "verdict": "not_listed"})
    return positions


def _add_text_position(positions: list[dict[str, str]], case: Bundle) -> None:
    """A text-only case has no range row. The human still needs the quote."""
    if case.method not in {"text_llm", "quarantine"} and not case.quote:
        return
    source = _advisory_source(case.record_id)
    if any(item.get("source") == source and item.get("quote") for item in positions):
        return
    if any(item.get("source") == source and item.get("verdict") in {"affected", "not_affected"} for item in positions):
        for item in positions:
            if item.get("source") != source:
                continue
            if case.record_id and not item.get("record_id"):
                item["record_id"] = case.record_id
            if case.quote and not item.get("quote"):
                item["quote"] = case.quote
            if case.text_bound and not item.get("bound"):
                item["bound"] = case.text_bound
        return
    item = {
        "source": source,
        "verdict": case.verdict or "uncertain",
        "record_id": case.record_id,
        "quote": case.quote,
    }
    if case.text_bound:
        item["bound"] = case.text_bound
    positions.append(item)


def _advisory_source(record_id: str) -> str:
    raw = record_id.split(":", 1)[0].lower() if record_id else ""
    if raw in {"cve_org", "cna"}:
        return "cna"
    if raw.startswith("nvd"):
        return "nvd"
    return raw or "cna"


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
