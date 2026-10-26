"""Reporter.

The JSON shape is what P4's patch list will read. It is written down in
`docs/project/ui.md`. Markdown is the same facts: score factors, confidence,
the needs-human questions, record ids, and receipts.

When the Critic accepts append-field under multer, the report says the
model decided the text does not apply to append-field, and the case is
not in the needs-human queue.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from sibyl.agents.prioritiser import PlacementResult


class ReportCase(BaseModel):
    case_id: str
    package: str = ""
    version: str = ""
    vuln_id: str = ""
    verdict: str
    score: float = 0
    score_factors: dict[str, float] = Field(default_factory=dict)
    confidence: float = 0
    confidence_factors: list[dict[str, Any]] = Field(default_factory=list)
    record_ids: list[str] = Field(default_factory=list)
    rationale: str = ""
    rationale_source: str = "deterministic"
    conflicts: list[dict[str, Any]] = Field(default_factory=list)
    question: str = ""
    accepted_under: str | None = None
    positions: list[dict[str, str]] = Field(default_factory=list)
    method: str = ""
    exploited: bool = False
    resolution: str = ""
    low_trust_flags: list[str] = Field(default_factory=list)
    ecosystem: str = ""
    purl: str = ""
    cvss: float = 0
    cvss_source: str = ""
    cvss_version: str = ""
    epss_percentile: float = 0


class Report(BaseModel):
    run_id: str
    state: str
    partial: bool = False
    degraded: bool = False
    unprocessed: list[str] = Field(default_factory=list)
    ranked: list[ReportCase] = Field(default_factory=list)
    closed: list[ReportCase] = Field(default_factory=list)
    needs_human: list[ReportCase] = Field(default_factory=list)
    receipts: dict[str, list[dict[str, Any]]] = Field(default_factory=lambda: {"zetaris": [], "llm": []})
    ingest: dict[str, Any] | None = None


def compile_report(
    *,
    run_id: str,
    state: str,
    placements: list[tuple[PlacementResult, dict[str, Any]]],
    unprocessed: list[str],
    degraded: bool,
    receipts: dict[str, list[dict[str, Any]]],
) -> Report:
    ranked: list[ReportCase] = []
    closed: list[ReportCase] = []
    needs_human: list[ReportCase] = []
    for placed, extra in placements:
        card = ReportCase(
            case_id=placed.case_id,
            package=extra.get("package", ""),
            version=extra.get("version", ""),
            vuln_id=extra.get("vuln_id", ""),
            verdict=placed.verdict,
            score=placed.score,
            score_factors=placed.components,
            confidence=placed.confidence,
            confidence_factors=extra.get("confidence_factors", []),
            record_ids=extra.get("record_ids", []),
            rationale=placed.rationale,
            rationale_source=placed.rationale_source,
            conflicts=extra.get("conflicts", []),
            question=placed.question,
            accepted_under=placed.accepted_under,
            positions=extra.get("positions", []),
            method=extra.get("method", ""),
            exploited=bool(extra.get("exploited")),
            resolution=str(extra.get("resolution") or ""),
            low_trust_flags=list(extra.get("low_trust_flags") or []),
            ecosystem=str(extra.get("ecosystem") or ""),
            purl=str(extra.get("purl") or ""),
            cvss=float(extra.get("cvss") or 0),
            cvss_source=str(extra.get("cvss_source") or ""),
            cvss_version=str(extra.get("cvss_version") or ""),
            epss_percentile=float(extra.get("epss_percentile") or 0),
        )
        if placed.placement == "ranked":
            ranked.append(card)
        elif placed.placement == "closed":
            closed.append(card)
        else:
            needs_human.append(card)
    ranked.sort(key=lambda card: card.score, reverse=True)
    return Report(
        run_id=run_id,
        state=state,
        partial=bool(unprocessed),
        degraded=degraded,
        unprocessed=unprocessed,
        ranked=ranked,
        closed=closed,
        needs_human=needs_human,
        receipts=receipts,
        ingest=None,
    )


def to_markdown(report: Report) -> str:
    lines = [f"# Sibyl report {report.run_id}", "", f"State: {report.state}"]
    if report.partial:
        lines.append("Partial: new work stopped. Unprocessed: " + ", ".join(report.unprocessed))
    if report.degraded:
        lines.append("Degraded: a source was missing. Confidence is lower.")
    lines.extend(["", "## Ranked"])
    if not report.ranked:
        lines.append("None.")
    for card in report.ranked:
        lines.append(
            f"- {card.package}@{card.version} {card.vuln_id}: {card.verdict}, "
            f"score {card.score} {card.score_factors}, confidence {card.confidence}. {card.rationale}"
        )
        if card.record_ids:
            lines.append("  records: " + ", ".join(card.record_ids))
        for conflict in card.conflicts:
            lines.append(f"  conflict ({conflict.get('severity')}): {conflict.get('values_by_source')}")
    lines.extend(["", "## Not affected"])
    if not report.closed:
        lines.append("None.")
    for card in report.closed:
        if card.accepted_under:
            lines.append(
                f"- {card.package}@{card.version} {card.vuln_id}: the model decided the text does not "
                f"apply to {card.package}. The finding is {card.accepted_under}. The Critic accepted that, "
                "so this case is not in the needs-human queue."
            )
        else:
            lines.append(
                f"- {card.package}@{card.version} {card.vuln_id}: {card.verdict}. {card.rationale}"
            )
    lines.extend(["", "## Needs human"])
    if not report.needs_human:
        lines.append("None.")
    for card in report.needs_human:
        lines.append(f"- {card.case_id}: {card.question}")
        for position in card.positions:
            detail = position.get("verdict") or ""
            if position.get("status") and position.get("status") != "active":
                detail = f"{detail} ({position.get('status')})"
            if position.get("bound"):
                detail = f"{detail} bound {position.get('bound')}"
            lines.append(f"  {position.get('source')}: {detail}")
    queries = report.receipts.get("zetaris") or []
    total_ms = sum(int(query.get("ms") or 0) for query in queries)
    core = next((str(query.get("sql") or "") for query in queries if "v_candidate_matches" in str(query.get("sql") or "")), "")
    lines.extend(["", "## Zetaris", "", f"{len(queries)} queries, {total_ms} ms."])
    if core:
        lines.extend(["", "Core view:", "", "```sql", core, "```"])
    lines.extend(["", "## Receipts"])
    for query in report.receipts.get("zetaris", []):
        lines.append(f"- zetaris rows={query.get('rows')} ms={query.get('ms')} sql={query.get('sql')}")
    for call in report.receipts.get("llm", []):
        extra = ""
        if call.get("agent"):
            extra += f" agent={call.get('agent')}"
        if call.get("reasoning_tokens") is not None:
            extra += f" reasoning_tokens={call.get('reasoning_tokens')}"
        if call.get("mode"):
            extra += f" mode={call.get('mode')}"
            if call.get("mode_honoured") is False:
                extra += " (not the requested mode)"
        if call.get("error_code"):
            extra += f" error={call.get('error_code')}"
        lines.append(
            f"- llm {call.get('lane')} requested={call.get('requested_model')} "
            f"routed={call.get('routed_model')} tokens={call.get('tokens')}{extra}"
        )
    return "\n".join(lines) + "\n"
