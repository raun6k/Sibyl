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
    conflicts: list[dict[str, Any]] = Field(default_factory=list)
    question: str = ""
    accepted_under: str | None = None
    positions: list[dict[str, str]] = Field(default_factory=list)


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
            conflicts=extra.get("conflicts", []),
            question=placed.question,
            accepted_under=placed.accepted_under,
            positions=extra.get("positions", []),
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
            lines.append(f"- {card.package}@{card.version} {card.vuln_id}: {card.verdict}.")
    lines.extend(["", "## Needs human"])
    if not report.needs_human:
        lines.append("None.")
    for card in report.needs_human:
        lines.append(f"- {card.case_id}: {card.question}")
        for position in card.positions:
            lines.append(f"  {position.get('source')}: {position.get('verdict')}")
    lines.extend(["", "## Receipts"])
    for query in report.receipts.get("zetaris", []):
        lines.append(f"- zetaris rows={query.get('rows')} ms={query.get('ms')} sql={query.get('sql')}")
    for call in report.receipts.get("llm", []):
        lines.append(
            f"- llm {call.get('lane')} requested={call.get('requested_model')} "
            f"routed={call.get('routed_model')} tokens={call.get('tokens')}"
        )
    return "\n".join(lines) + "\n"
