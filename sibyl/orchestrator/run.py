"""Run the triage state machine.

`PLANNED → COLLECTING → MAPPING → MATCHING → CRITIQUE ⇄ MATCHING →
PRIORITISING → REPORTING → DONE`. A Zetaris failure during collection
ends the run as `FAILED`. Over the time or token budget, new cases stop
and the report is partial, with the unprocessed ids listed.

The Critic gets at most two rounds. A second recheck escalates with both
positions. The Matcher re-reads a description only on a send-back.

Every case goes through the World Model: the Mapper writes its claims, the
Matcher its drafts and conflicts, and the Critic, the Prioritiser and the
Reporter read `world.case()` back. An incremental run sends only cases whose
verdict fingerprint changed to the Matcher and the Critic; the rest keep
their earlier verdict, re-scored, and the trace and report name them. The
report is the World Model's `report` view of this run.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Sequence
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextvars import copy_context
from datetime import datetime, timezone
from typing import Any

from sibyl.agents.critic import CaseView, CriticResult, review_case
from sibyl.agents.matcher import DraftVerdict, MatchResult, match, revise_from_description
from sibyl.agents.prioritiser import PlacementResult, prioritise, prioritise_case, record_priority, write_model_rationales
from sibyl.agents.reporter import Report, card_for, report_view
from sibyl.agents.scout import screen_advisory
from sibyl.config import Settings, load_settings
from sibyl.engines.hmem import HmemClient
from sibyl.engines.messages import Escalation, Placement, RunClosed, RunOpened, Verdict
from sibyl.engines.trust import TrustTable, reset_table
from sibyl.engines.world_model import WorldModelClient
from sibyl.llm.client import MAX_IN_FLIGHT, LLMUnavailable, TokenBudget
from sibyl.orchestrator import casefile
from sibyl.orchestrator.casefile import Bundle
from sibyl.orchestrator.incremental import Plan, Planner, reuse
from sibyl.orchestrator.log import RunLog
from sibyl.scoring import confidence as confidence_of
from sibyl.scoring import trust_weight
from sibyl.tools.zetaris import run_sql, sql_actor

__all__ = ["Bundle", "Clock", "ingest_advisories", "run_triage"]


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
    incremental: bool = False,
    services: list[str] | None = None,
    receipts: dict[str, list[dict[str, Any]]] | None = None,
    covers: list[str] | None = None,
    rationale_batch: Callable[[list[list[dict[str, str]]]], list[Any]] | None = None,
) -> Report:
    """Triage the cases. Without a World Model a memory-only one serves this run alone.

    `incremental` reuses verdicts whose fingerprint did not change; it needs a
    World Model that remembers earlier runs. `services` names the services
    this run covers (None is the whole workspace). `receipts` are the lists
    the caller fills with Zetaris and model receipts; the report keeps them.
    `covers` overrides which services the run counts as covered in the case
    state (a point question covers none). `rationale_batch` writes model
    rationales through one Nightshift batch job first.
    """
    active = settings or load_settings()
    trace = log or RunLog(active)
    if trace.run_id is None:
        trace.start({"kind": "triage"}, {"max_tokens": active.run_max_tokens, "max_seconds": active.run_max_seconds})
    run_id = trace.run_id or str(uuid.uuid4())
    timer = clock or Clock()
    tokens = budget or TokenBudget(active.run_max_tokens)
    kept = receipts if receipts is not None else {"zetaris": [], "llm": []}
    kept.setdefault("zetaris", [])
    kept.setdefault("llm", [])
    table = TrustTable(hmem, active)
    token = table.bind()
    own_world = world is None
    model = world if world is not None else WorldModelClient(namespace=f"run-{run_id}")
    ingest_report: dict[str, Any] | None = None
    scope = covers if covers is not None else services
    try:
        model.run_opened(
            RunOpened(
                run_id=run_id,
                workspace_id=active.workspace_id,
                services=sorted(scope) if scope is not None else None,
                incremental=incremental,
                at=_now(),
            )
        )
        if not own_world:
            ingest_report = ingest_advisories(active, model)
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
                model.run_closed(RunClosed(run_id=run_id, state="FAILED", receipts=kept, ingest=ingest_report))
                return report_view(model, run_id)
            _state(trace, "COLLECTING", "MAPPING")
            _state(trace, "MAPPING", "MATCHING")
        if services is not None:
            wanted = set(services)
            cases = [case for case in cases if casefile.service_of(case.case_id) in wanted]
        degraded = any(case.disabled for case in cases)
        planner = Planner(model, active, hmem, run_id, incremental=incremental)
        plan = planner.plan(cases)
        _trace_plan(trace, plan, incremental)
        fresh = [case for case in cases if case.case_id not in plan.reused]
        placements, unprocessed = _run_cases(fresh, active, timer, tokens, llm, trace, hmem, model, run_id, plan)
        if unprocessed:
            trace.decision("orchestrator", "budget exhausted", unprocessed=unprocessed)
        kept_rationales: set[str] = set()
        for case in cases:
            prior = plan.reused.get(case.case_id)
            if prior is None:
                continue
            placed, card, moved = reuse(prior, plan.projections[case.case_id], active)
            if not moved:
                kept_rationales.add(placed.case_id)
            placements.append((placed, card))
        if placements and not _over_budget(active, timer, tokens):
            write_model_rationales(
                [placed for placed, _extra_fields in placements],
                llm,
                allow=lambda: not _over_budget(active, timer, tokens),
                keep=kept_rationales,
                batch=rationale_batch,
            )
        _state(trace, "MATCHING", "REPORTING")
        _write_placements(model, run_id, placements, plan)
        model.run_closed(
            RunClosed(
                run_id=run_id,
                state="DONE",
                partial=bool(unprocessed),
                degraded=degraded,
                unprocessed=unprocessed,
                reused=sorted(plan.reused),
                receipts=kept,
                ingest=ingest_report,
            )
        )
        report = report_view(model, run_id)
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
        if own_world:
            model.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _trace_plan(trace: RunLog, plan: Plan, incremental: bool) -> None:
    """One `reuse` event per kept verdict, and one decision that sums the plan up."""
    for case_id, prior in sorted(plan.reused.items()):
        card = prior.get("card") or {}
        trace.event(
            "world_model",
            "reuse",
            {
                "case_id": case_id,
                "from_run": prior.get("reused_from") or prior.get("run_id"),
                "verdict": card.get("verdict"),
                "placement": prior.get("placement"),
                "reason": "claims and component unchanged since the accepted verdict",
            },
        )
    counts: dict[str, int] = {}
    for reason in plan.reasons.values():
        counts[reason] = counts.get(reason, 0) + 1
    trace.decision(
        "orchestrator",
        "incremental plan" if incremental else "full run",
        reused=len(plan.reused),
        triaged=len(plan.reasons),
        why=counts,
    )


def _write_placements(
    world: WorldModelClient,
    run_id: str,
    placements: list[tuple[PlacementResult, dict[str, Any]]],
    plan: Plan,
) -> None:
    messages: list[tuple[str, Any]] = []
    for placed, extra in placements:
        card = card_for(placed, extra)
        messages.append(
            (
                "placement",
                Placement(
                    run_id=run_id,
                    case_id=placed.case_id,
                    placement=placed.placement if placed.placement in {"ranked", "closed"} else "needs_human",
                    card=card.model_dump(),
                    fingerprint=plan.fingerprints.get(placed.case_id, ""),
                    reused_from=extra.get("reused_from"),
                ),
            )
        )
        if len(messages) >= 100:
            world.write(messages)
            messages = []
    world.write(messages)


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
    hmem: HmemClient | None,
    world: WorldModelClient,
    run_id: str,
    plan: Plan,
) -> tuple[list[tuple[PlacementResult, dict[str, Any]]], list[str]]:
    """Critique each case. At most four run at once, and a spent budget starts no new one."""
    results: dict[int, tuple[PlacementResult, dict[str, Any]]] = {}
    unprocessed: list[str] = []
    pending = list(enumerate(cases))
    inflight: dict = {}

    def _one(case: Bundle) -> tuple[PlacementResult, dict[str, Any]]:
        placed, extra_fields = _process_case(case, active, llm, trace, hmem, world, run_id)
        _note_history(extra_fields, plan.projections.get(case.case_id))
        return placed, extra_fields

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


def _note_history(extra_fields: dict[str, Any], projection: dict[str, Any] | None) -> None:
    """What the run before decided, from the World Model's case history."""
    if not projection:
        return
    history = projection.get("history") or []
    if not history:
        return
    last = history[0]
    extra_fields["previous_verdict"] = last.get("verdict") or ""
    extra_fields["previous_run"] = last.get("reused_from") or last.get("run_id") or ""
    extra_fields["rechecks_before"] = sum(len(item.get("rechecks") or []) for item in history)


def _process_case(
    case: Bundle,
    active: Settings,
    llm: object | None,
    trace: RunLog,
    hmem: HmemClient | None,
    world: WorldModelClient,
    run_id: str,
) -> tuple[PlacementResult, dict[str, Any]]:
    remembered = hmem.resolution_for(case.case_id) if hmem is not None else None
    if remembered and remembered.get("scope", "this_case") == "this_case":
        return _from_memory(case, remembered, active, trace, world, run_id)
    outcome = match(case.rows) if case.rows else MatchResult()
    if case.method == "text_llm" and not any(
        verdict.case_id == case.case_id and verdict.source == "combined" for verdict in outcome.verdicts
    ):
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
    _write_match(world, case, outcome, run_id)
    _state(trace, "MATCHING", "CRITIQUE")
    if active.critic_enabled:
        decision = _critique(case, llm, trace, world, run_id)
    else:
        decision = _uncritiqued(case, trace, world, run_id)
    extra_done = not active.critic_enabled
    placed, view = prioritise_case(
        world, case.case_id, decision, run_id=run_id, llm=llm, settings=active, extra_check_done=extra_done, disabled=case.disabled
    )
    if placed.placement == "recheck":
        extra_done = True
        extra, _ = review_case(world, case.case_id, run_id=run_id, round=2, llm=llm, disabled=case.disabled)
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
        placed, view = prioritise_case(
            world, case.case_id, decision, run_id=run_id, llm=llm, settings=active, extra_check_done=extra_done, disabled=case.disabled
        )
    _state(trace, "CRITIQUE", "PRIORITISING")
    # The Reporter's card comes from the case as the World Model holds it now.
    projection = world.case(case.case_id, run_id)
    stored = casefile.bundle_from_case(projection, disabled=case.disabled)
    final = casefile.outcome_from_case(projection)
    extra_fields = casefile.extra(stored, final, casefile.positions(final, stored))
    extra_fields["resolution"] = "critic" if decision.action == "accept" else "unresolved"
    flags = _low_trust_flags(view)
    if flags:
        extra_fields["low_trust_flags"] = flags
    if decision.flags:
        extra_fields["flags"] = list(decision.flags)
    world.verdict(
        Verdict(
            case_id=case.case_id,
            verdict=placed.verdict if placed.verdict in {"affected", "not_affected"} else "uncertain",  # type: ignore[arg-type]
            confidence=placed.confidence,
            resolution=extra_fields["resolution"],
            run_id=run_id,
        )
    )
    _state(trace, "PRIORITISING", "MATCHING")
    return placed, extra_fields


def _write_match(world: WorldModelClient, case: Bundle, outcome: MatchResult, run_id: str, round: int = 0) -> None:
    """The Matcher's round for this case, with its text reading on round 0."""
    messages: list[tuple[str, Any]] = []
    if round == 0:
        draft = casefile.text_draft(case, run_id)
        if draft is not None:
            messages.append(("draft_verdict", draft))
    messages.extend(casefile.outcome_messages(outcome, case.case_id, run_id, round))
    world.write(messages)


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


def _from_memory(
    case: Bundle,
    remembered: dict[str, Any],
    active: Settings,
    trace: RunLog,
    world: WorldModelClient,
    run_id: str,
) -> tuple[PlacementResult, dict[str, Any]]:
    """A stored human resolution decides the case. It is not sent to the Critic again."""
    decision_name = str(remembered.get("decision") or "uncertain")
    verdict = decision_name if decision_name in {"affected", "not_affected", "uncertain"} else "not_affected"
    if decision_name == "accept_risk":
        verdict = "not_affected"
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
    _write_match(world, case, outcome, run_id)
    scored = confidence_of(trust=1.0)
    decision = CriticResult(
        case_id=case.case_id,
        action="accept",
        reason=str(remembered.get("note") or "a human resolution decided this case"),
        round=0,
        check="memory",
    )
    projection = world.case(case.case_id, run_id)
    stored = casefile.bundle_from_case(projection, disabled=case.disabled)
    stored.method = "memory"
    stored.verdict = verdict
    final = casefile.outcome_from_case(projection)
    view = casefile.view_of(stored, final)
    view.method = "memory"
    view.verdict = verdict
    view.confidence = 1.0
    placed = prioritise(view, decision, llm=None, settings=active)
    placed = _remembered_placement(placed, verdict)
    placed.confidence = 1.0
    record_priority(world, placed, run_id=run_id)
    trace.decision(
        "memory",
        decision.reason,
        case_id=case.case_id,
        resolution="memory",
        action="accept",
        check="memory",
    )
    extra = casefile.extra(stored, final, casefile.positions(final, stored))
    extra["method"] = "memory"
    extra["resolution"] = "memory"
    extra["confidence_factors"] = [factor.model_dump() for factor in scored.factors] + [
        {"name": "human_resolution", "value": 1.0, "note": decision.reason},
    ]
    flags = _low_trust_flags(view)
    if flags:
        extra["low_trust_flags"] = flags
    world.verdict(
        Verdict(
            case_id=case.case_id,
            verdict=verdict if verdict in {"affected", "not_affected"} else "uncertain",  # type: ignore[arg-type]
            confidence=1.0,
            resolution="memory",
            run_id=run_id,
        )
    )
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


def _uncritiqued(case: Bundle, trace: RunLog, world: WorldModelClient, run_id: str) -> CriticResult:
    """The critic is off. The Matcher's verdict is accepted as drafted.

    A blocking conflict still goes to needs-human, because the Prioritiser
    places it there; nothing re-reads or resolves it.
    """
    from sibyl.engines.messages import CriticDecision

    decision = CriticResult(
        case_id=case.case_id,
        action="accept",
        reason="critic disabled",
        round=0,
        check="disabled",
    )
    trace.decision("critic", decision.reason, action="accept", round=0, check="disabled", case_id=case.case_id)
    world.critic_decision(CriticDecision(case_id=case.case_id, decision="accept", reason=decision.reason, round=0, run_id=run_id))
    return decision


def _critique(
    case: Bundle,
    llm: object | None,
    trace: RunLog,
    world: WorldModelClient,
    run_id: str,
) -> CriticResult:
    decision = CriticResult(case_id=case.case_id, action="reject", reason="no review", round=0, check="none")
    for round_number in (1, 2):
        decision, _view = review_case(world, case.case_id, run_id=run_id, round=round_number, llm=llm, disabled=case.disabled)
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
            return decision
        if decision.action == "recheck" and decision.to == "matcher" and round_number < 2 and llm is not None and decision.check != "withdrawn":
            if case.method != "text_llm" and screen_advisory(case.description).flagged:
                # The structured rows decide. A second round escalates with them.
                trace.event(
                    "matcher",
                    "quarantine",
                    {"case_id": case.case_id, "round": round_number, "reason": "instructions in the description"},
                )
                continue
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
            try:
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
            except LLMUnavailable as exc:
                # The model did not answer: no re-read this round. The second round escalates with the rows.
                trace.event("matcher", "revision_failed", {"case_id": case.case_id, "round": round_number, "reason": str(exc)[:300]})
                continue
            _write_match(world, case, current, run_id, round=round_number)
            trace.event(
                "matcher",
                "revision",
                {"case_id": case.case_id, "quote": quote, "round": round_number},
            )
            continue
        break
    projection = world.case(case.case_id, run_id)
    current = casefile.outcome_from_case(projection)
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
        return decision
    stored = casefile.bundle_from_case(projection, disabled=case.disabled)
    positions = casefile.positions(current, stored)
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
    world.escalation(
        Escalation(case_id=case.case_id, question=decision.reason, evidence_needed="which source decides this version", run_id=run_id)
    )
    return decision


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


def _state(trace: RunLog, before: str, after: str) -> None:
    trace.transition(before, after)


def _over_budget(settings: Settings, clock: Clock, budget: TokenBudget) -> bool:
    if settings.run_max_seconds > 0 and clock.elapsed() >= settings.run_max_seconds:
        return True
    return budget.exhausted
