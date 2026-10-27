"""World Model messages.

The shapes are the ones in `docs/project/agents.md`. `CriticDecision.decision`
is the accept/reject alternative. `SourceMap.fields` is the field to
authoritative-source map. `RecheckRequest` keeps the JSON name `from`.

Messages a run writes carry its `run_id`, so the same verdict in a later run
is a new event and a case's history keeps every run. Claims carry no run:
they are facts about the advisories and the inventory, and an unchanged
claim is an empty diff.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

VerdictName = Literal["affected", "not_affected", "uncertain"]
Resolution = Literal["rule", "memory", "critic", "human", "unresolved"]


class Claim(BaseModel):
    case_id: str
    source: str
    field: str
    value: Any
    raw_ref: str
    retrieved_at: str
    source_status: str


class AliasLink(BaseModel):
    vuln_id: str
    alias_id: str
    source: str
    confidence: float


class SourceMap(BaseModel):
    case_id: str
    fields: dict[str, str]
    gaps: list[str]


class DraftVerdict(BaseModel):
    case_id: str
    verdict: VerdictName
    basis: list[str]
    method: Literal["range_eval", "text_llm", "memory", "quarantine"]
    confidence: float
    run_id: str = ""
    # `combined` is the Matcher's case verdict; a source name is that source's own reading.
    source: str = "combined"
    round: int = 0
    quote: str = ""
    applies_to_package: bool | None = None
    text_bound: str = ""
    related_affected: str | None = None


class Conflict(BaseModel):
    case_id: str
    field: str
    values_by_source: dict[str, str]
    severity: Literal["blocking", "informational"]
    run_id: str = ""
    round: int = 0


class RecheckRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    case_id: str
    origin: str = Field(alias="from")
    to: str
    reason: str
    round: int
    run_id: str = ""


class CriticDecision(BaseModel):
    case_id: str
    decision: Literal["accept", "reject"]
    reason: str
    round: int
    run_id: str = ""


class Verdict(BaseModel):
    case_id: str
    verdict: VerdictName
    confidence: float
    resolution: Resolution
    run_id: str = ""


class PriorityComponents(BaseModel):
    exploited: float
    epss: float
    severity: float
    exposure: float
    criticality: float


class Priority(BaseModel):
    case_id: str
    score: float
    components: PriorityComponents
    rationale: str
    run_id: str = ""


class Escalation(BaseModel):
    case_id: str
    question: str
    evidence_needed: str
    run_id: str = ""


class RunOpened(BaseModel):
    run_id: str
    workspace_id: str = ""
    # The services this run covers; None is every service in the workspace.
    services: list[str] | None = None
    incremental: bool = True
    at: str = ""


class Placement(BaseModel):
    """Where a run put one case, with the report card. The report view reads these."""

    run_id: str
    case_id: str
    placement: Literal["ranked", "closed", "needs_human"]
    card: dict[str, Any]
    fingerprint: str = ""
    reused_from: str | None = None


class RunClosed(BaseModel):
    run_id: str
    state: str
    partial: bool = False
    degraded: bool = False
    unprocessed: list[str] = Field(default_factory=list)
    reused: list[str] = Field(default_factory=list)
    receipts: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    ingest: dict[str, Any] | None = None


class Diff(BaseModel):
    changed: bool
    ids: list[str] = Field(default_factory=list)
