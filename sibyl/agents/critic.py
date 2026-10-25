"""Conflict Critic.

Checks run in the order in `docs/project/agents.md`. Authority, material
disagreement, a degraded source, and a withdrawn record are code. Whether
an extracted quote supports the claim is the deep lane.

A NVD CPE bound that disagrees with a version in the same record's
description is a send-back to the Matcher. NVD disagreeing on its own,
when the description matches the CPE, stays informational.

append-field is not affected: the model decided the text does not apply
to that package. The Critic accepts it under the multer finding.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

from sibyl.agents.prompts import load_prompt
from sibyl.scoring import trust_weight
from sibyl.tools.version_eval import is_affected

Action = Literal["accept", "reject", "recheck"]
_VERSION = re.compile(r"\b\d+\.\d+\.\d+\b")
_UPPER = re.compile(
    r"(?:through|before|prior to|up to|and earlier|versions?)\s+(?:version\s+)?$",
    re.IGNORECASE,
)
_FIX = re.compile(r"(?:fixed|patched|upgrade[sd]?|updated)\s+in\s+$", re.IGNORECASE)
_AUTHORITY = ("osv", "ghsa", "cna")
_WITHDRAWN = {"withdrawn", "rejected"}


class Side(BaseModel):
    source: str
    verdict: str
    introduced: str = ""
    fixed: str = ""
    last_affected: str = ""
    status: str = "active"
    cna_silence: bool = False


class CaseView(BaseModel):
    case_id: str
    package: str
    version: str
    ecosystem: str
    vuln_id: str
    verdict: str
    confidence: float
    method: str
    basis: list[str] = Field(default_factory=list)
    sides: list[Side] = Field(default_factory=list)
    description: str = ""
    quote: str = ""
    applies_to_package: bool | None = None
    conflict_severity: str = ""
    disabled: list[str] = Field(default_factory=list)
    related_affected: str | None = None
    osv_not_listed: bool = False
    internet_facing: bool = False
    criticality: float = 0
    exploited: bool = False
    epss_percentile: float = 0
    cvss: float = 0
    cvss_source: str = ""
    cvss_version: str = ""
    purl: str = ""
    text_bound: str = ""


class QuoteJudgement(BaseModel):
    supported: bool
    reason: str = ""


class CriticResult(BaseModel):
    case_id: str
    action: Action
    reason: str
    round: int
    to: Literal["mapper", "matcher"] | None = None
    check: str
    accepted_under: str | None = None
    degraded: bool = False
    flags: list[str] = Field(default_factory=list)


def review(view: CaseView, *, round: int, llm: object | None = None) -> CriticResult:
    """One pass of the four checks. The first failure is the result.

    A human resolution, or any higher-trust verdict, is not replaced by a
    lower-trust claim. The disagreement is flagged and the verdict stays.
    """
    if view.method == "memory":
        flags = [
            f"{side.source} cannot overturn a human resolution"
            for side in view.sides
            if side.verdict in {"affected", "not_affected"} and side.verdict != view.verdict
        ]
        return CriticResult(
            case_id=view.case_id,
            action="accept",
            reason="a human resolution decided this case",
            round=round,
            check="memory",
            flags=flags,
        )
    failed = _authority(view, round) or _disagreement(view, round) or _quote(view, round, llm) or _missing(view, round)
    if failed is not None:
        return failed
    under = None
    reason = "the authoritative source supports the verdict"
    nvd = next((side for side in view.sides if side.source == "nvd"), None)
    if view.osv_not_listed and nvd is not None and nvd.verdict == "not_affected":
        reason = "OSV was queried for this purl and did not list the CVE; NVD says not affected"
    if view.verdict == "not_affected" and view.applies_to_package is False and view.related_affected:
        under = view.related_affected
        reason = (
            f"the model decided the text does not apply to {view.package}; "
            f"the finding is {view.related_affected}"
        )
    return CriticResult(
        case_id=view.case_id,
        action="accept",
        reason=reason,
        round=round,
        check="accept",
        accepted_under=under,
        degraded=_higher_authority_missing(view),
    )


def _authority(view: CaseView, round: int) -> CriticResult | None:
    authority = _authority_side(view)
    if authority is None or authority.verdict == "uncertain":
        return None
    if authority.verdict != view.verdict:
        return _recheck(view, round, "authority", f"{authority.source} says {authority.verdict}")
    return None


def _disagreement(view: CaseView, round: int) -> CriticResult | None:
    decided = [side for side in view.sides if side.verdict in {"affected", "not_affected"}]
    # A withdrawn record is its own check. It is not a range disagreement.
    authority = [
        side
        for side in decided
        if side.source in _AUTHORITY and side.status not in _WITHDRAWN and not side.cna_silence
    ]
    if len({side.verdict for side in authority}) > 1:
        return _recheck(view, round, "disagreement", "authority sources disagree at this version")
    nvd = next((side for side in decided if side.source == "nvd"), None)
    if nvd is None or not view.description:
        return None
    if _text_contradicts_cpe(view, nvd):
        return _recheck(
            view,
            round,
            "disagreement",
            "the NVD CPE bound contradicts a version in the same record's description",
        )
    return None


def _quote(view: CaseView, round: int, llm: object | None) -> CriticResult | None:
    if view.method != "text_llm":
        return None
    if not view.quote or view.quote not in view.description:
        return CriticResult(
            case_id=view.case_id,
            action="reject",
            reason="the extracted quote is not in the source text",
            round=round,
            check="quote",
        )
    if llm is None:
        return None
    import json

    judgement = llm.complete(
        "deep",
        [
            {"role": "system", "content": load_prompt("critic")},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "package": view.package,
                        "verdict": view.verdict,
                        "applies_to_package": view.applies_to_package,
                        "quote": view.quote,
                        "text": view.description,
                    }
                ),
            },
        ],
        QuoteJudgement,
    )
    if view.verdict == "affected" and not judgement.output.supported:
        return _recheck(view, round, "quote", judgement.output.reason or "the quote does not support affected")
    return None


def _missing(view: CaseView, round: int) -> CriticResult | None:
    if view.verdict == "affected" and any(side.status in _WITHDRAWN for side in view.sides):
        return _recheck(view, round, "withdrawn", "a withdrawn or rejected record is set against an affected verdict")
    nvd = next((side for side in view.sides if side.source == "nvd" and side.verdict in {"affected", "not_affected"}), None)
    others = [side for side in view.sides if side.source in _AUTHORITY and side.verdict in {"affected", "not_affected"}]
    if view.osv_not_listed and nvd is not None and not others:
        if nvd.verdict == "affected":
            return _recheck(
                view,
                round,
                "osv_silence",
                "OSV was queried for this purl and did not list the CVE; NVD says affected",
            )
    return None


def _upper_bound_versions(text: str) -> set[str]:
    """Versions the prose states as a vulnerable upper bound, not a fix."""
    found: set[str] = set()
    for match in _VERSION.finditer(text or ""):
        before = text[max(0, match.start() - 48) : match.start()].lower()
        if _FIX.search(before):
            continue
        if _UPPER.search(before):
            found.add(match.group(0))
    return found


def _text_contradicts_cpe(view: CaseView, nvd: Side) -> bool:
    bounds = {nvd.introduced, nvd.fixed, nvd.last_affected} - {""}
    extra = _upper_bound_versions(view.description) - bounds
    if nvd.verdict != "not_affected" and nvd.verdict != "affected":
        return False
    for token in extra:
        decided = is_affected(
            view.ecosystem,
            view.version,
            [{"introduced": "0", "fixed": "", "last_affected": token, "raw_range": "", "range_type": ""}],
        )
        if decided is True and nvd.verdict != "affected":
            return True
        if decided is False and nvd.verdict == "affected":
            return True
    return False


def _authority_side(view: CaseView) -> Side | None:
    """The highest-trust source that has a verdict. Ties keep OSV, then GHSA, then CNA."""
    ranked: list[tuple[float, int, Side]] = []
    for index, name in enumerate(_AUTHORITY):
        for side in view.sides:
            if side.source == name and side.verdict in {"affected", "not_affected"}:
                ranked.append((trust_weight(side.source, field="affected_ranges", ecosystem=view.ecosystem or "*"), -index, side))
    if not ranked:
        return None
    ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return ranked[0][2]


def _higher_authority_missing(view: CaseView) -> bool:
    disabled = {name.lower() for name in view.disabled}
    chosen = _authority_side(view)
    if chosen is None:
        return "osv" in disabled
    for name in _AUTHORITY:
        if name == chosen.source:
            return False
        if name in disabled:
            return True
    return False


def _recheck(view: CaseView, round: int, check: str, reason: str) -> CriticResult:
    # OSV silence is a disagreement to show a human, not a range to re-read.
    if check == "osv_silence":
        return CriticResult(
            case_id=view.case_id,
            action="reject",
            reason=reason,
            round=round,
            check=check,
        )
    target: Literal["mapper", "matcher"] = "matcher" if check != "alias" else "mapper"
    return CriticResult(
        case_id=view.case_id,
        action="recheck",
        reason=reason,
        round=round,
        to=target,
        check=check,
    )
