"""World Model messages.

The shapes are the ones in `docs/project/agents.md`. `CriticDecision.decision`
is the accept/reject alternative. `SourceMap.fields` is the field to
authoritative-source map. `RecheckRequest` keeps the JSON name `from`.
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


class Conflict(BaseModel):
    case_id: str
    field: str
    values_by_source: dict[str, str]
    severity: Literal["blocking", "informational"]


class RecheckRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    case_id: str
    origin: str = Field(alias="from")
    to: str
    reason: str
    round: int


class CriticDecision(BaseModel):
    case_id: str
    decision: Literal["accept", "reject"]
    reason: str
    round: int


class Verdict(BaseModel):
    case_id: str
    verdict: VerdictName
    confidence: float
    resolution: Resolution


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


class Escalation(BaseModel):
    case_id: str
    question: str
    evidence_needed: str


class Diff(BaseModel):
    changed: bool
    ids: list[str] = Field(default_factory=list)
