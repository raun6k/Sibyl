"""Incremental triage on both axes (D13).

A case goes to the Matcher and the Critic only when what decides its
verdict changed since its last accepted verdict: an advisory claim (a
range, a withdrawn record, the description, OSV's answer), or the
component edge in the inventory (a new version closes the old edge; a
version that comes back opens a new one). Everything else reuses the
World Model verdict and is only re-scored, because KEV, EPSS and CVSS move
the priority, not the verdict.

A human resolution, a changed trust table, a disabled source or the critic
switch are part of the fingerprint too, so any of them re-decides the case.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sibyl.agents.prioritiser import PlacementResult, deterministic_rationale
from sibyl.config import Settings
from sibyl.inventory.purls import purl_slot
from sibyl.orchestrator.casefile import Bundle, case_claims, fingerprint, priority_inputs, service_of
from sibyl.scoring import priority_score

_CHUNK = 100
# Placements a later run may reuse: the Critic (or a stored human answer) accepted them.
_ACCEPTED = {"ranked", "closed"}


@dataclass
class Plan:
    fingerprints: dict[str, str] = field(default_factory=dict)
    # case id -> the earlier placement whose verdict this run keeps
    reused: dict[str, dict[str, Any]] = field(default_factory=dict)
    projections: dict[str, dict[str, Any]] = field(default_factory=dict)
    # case id -> why it is re-decided: new, changed, needs_human, ...
    reasons: dict[str, str] = field(default_factory=dict)


class Planner:
    """Writes each case's claims, then decides which cases this run can reuse."""

    def __init__(self, world: Any, settings: Settings, hmem: Any | None, run_id: str, *, incremental: bool = True) -> None:
        self.world = world
        self.settings = settings
        self.hmem = hmem
        self.run_id = run_id
        self.incremental = incremental
        self._edges: dict[str, dict[str, dict[str, Any]]] = {}
        self._written: set[str] = set()
        self._trust: str | None = None
        self._resolutions: dict[str, Any] = {}

    def record(self, cases: Sequence[Bundle]) -> None:
        """The Mapper's claims for each case. Unchanged claims are empty diffs."""
        pending = [case for case in cases if case.case_id not in self._written]
        for start in range(0, len(pending), _CHUNK):
            batch = pending[start : start + _CHUNK]
            self.world.write([("claim", claim) for case in batch for claim in case_claims(case)])
            self._written.update(case.case_id for case in batch)

    def plan(self, cases: Sequence[Bundle]) -> Plan:
        self.record(cases)
        result = Plan()
        ids = [case.case_id for case in cases]
        by_id = {case.case_id: case for case in cases}
        for start in range(0, len(ids), _CHUNK):
            for projection in self.world.cases(ids[start : start + _CHUNK], self.run_id):
                case_id = str(projection.get("case_id") or "")
                case = by_id.get(case_id)
                if case is None:
                    continue
                result.projections[case_id] = projection
                printed = fingerprint(projection, self.context(case))
                result.fingerprints[case_id] = printed
                prior = projection.get("prior")
                reason = self._reason(prior, printed)
                if reason == "unchanged":
                    result.reused[case_id] = prior  # type: ignore[assignment]
                else:
                    result.reasons[case_id] = reason
        return result

    def reusable(self, cases: Sequence[Bundle]) -> set[str]:
        """Case ids whose verdict this run keeps. Used before the Matcher reads text."""
        if not self.incremental:
            self.record(cases)
            return set()
        return set(self.plan(cases).reused)

    def context(self, case: Bundle) -> dict[str, Any]:
        service = service_of(case.case_id)
        edge = self._edge(service, purl_slot(case.purl)) if case.purl else None
        return {
            "disabled": sorted(case.disabled),
            "resolution": self._resolution(case.case_id),
            "trust": self._trust_digest(),
            "critic": self.settings.critic_enabled,
            "edge": (edge or {}).get("validFrom") or "",
        }

    def _reason(self, prior: Any, printed: str) -> str:
        if not isinstance(prior, dict):
            return "new"
        if not self.incremental:
            return "full run"
        if prior.get("placement") not in _ACCEPTED:
            return str(prior.get("placement") or "not accepted")
        card = prior.get("card") if isinstance(prior.get("card"), dict) else {}
        if str(card.get("resolution") or "") in {"", "unresolved"}:
            return "not accepted"
        if prior.get("fingerprint") != printed:
            return "changed"
        return "unchanged"

    def _edge(self, service: str, slot: str) -> dict[str, Any] | None:
        if service not in self._edges:
            found = self.world.edges(f"service:{service}", via="uses")
            self._edges[service] = {str(edge.get("slot") or ""): edge for edge in found}
        return self._edges[service].get(slot)

    def _resolution(self, case_id: str) -> Any:
        if self.hmem is None:
            return None
        if case_id not in self._resolutions:
            try:
                self._resolutions[case_id] = self.hmem.resolution_for(case_id)
            except Exception:
                self._resolutions[case_id] = None
        return self._resolutions[case_id]

    def _trust_digest(self) -> str:
        if self._trust is None:
            table: Any = self.settings.trust_weights
            if self.hmem is not None:
                try:
                    table = self.hmem.snapshot().get("trust") or table
                except Exception:
                    pass
            self._trust = hashlib.sha256(json.dumps(table, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
        return self._trust


def reuse(prior: dict[str, Any], projection: dict[str, Any], settings: Settings) -> tuple[PlacementResult, dict[str, Any], bool]:
    """Keep an earlier verdict and re-score it from today's KEV, EPSS, CVSS and service facts.

    Returns the placement, the card fields, and whether the score moved.
    """
    card = dict(prior.get("card") or {})
    inputs = priority_inputs(projection)
    scored = priority_score(
        exploited=inputs["exploited"],
        epss_percentile=inputs["epss_percentile"],
        cvss=inputs["cvss"],
        internet_facing=inputs["internet_facing"],
        criticality=inputs["criticality"],
        settings=settings,
    )
    moved = abs(float(card.get("score") or 0) - scored.score) > 1e-9
    rationale = str(card.get("rationale") or "")
    source = str(card.get("rationale_source") or "deterministic")
    placement = str(prior.get("placement") or "closed")
    if moved and placement == "ranked":
        rationale = deterministic_rationale(scored.score, scored.components, float(card.get("confidence") or 0))
        source = "deterministic"
    placed = PlacementResult(
        case_id=str(card.get("case_id") or prior.get("case_id") or ""),
        verdict=str(card.get("verdict") or "uncertain"),
        score=scored.score,
        components=scored.components,
        confidence=float(card.get("confidence") or 0),
        placement=placement,  # type: ignore[arg-type]
        rationale=rationale,
        rationale_source=source,  # type: ignore[arg-type]
        question=str(card.get("question") or ""),
        accepted_under=card.get("accepted_under"),
    )
    card.update(
        {
            "exploited": inputs["exploited"],
            "epss_percentile": inputs["epss_percentile"],
            "cvss": inputs["cvss"],
            "cvss_source": inputs["cvss_source"],
            "cvss_version": inputs["cvss_version"],
            "reused_from": prior.get("reused_from") or prior.get("run_id"),
            "previous_verdict": card.get("verdict") or "",
            "previous_run": prior.get("run_id") or "",
        }
    )
    return placed, card, moved
