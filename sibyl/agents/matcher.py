"""Matcher.

`match` is the deterministic range rule and does not call a model.
`evaluate` wraps it: structured rows stay `range_eval`, and text with no
structured range is extracted on the deep lane and then decided by
`version_eval`. The model does not choose affected or not.


Authority for `affected_ranges` is OSV, then GHSA, then the CVE.org CNA.
NVD CPE is reported per source and never decides the combined draft on its own.
A withdrawn or rejected record cannot produce `affected`.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Literal

from pydantic import BaseModel, Field

from sibyl.config import Settings
from sibyl.tools.version_eval import is_affected
from sibyl.tools.zetaris import ResultTruncated, SqlResult, run_sql

CANDIDATE_PAGE_LIMIT = 50000
SERVICE_SQL = "SELECT service_id FROM acme_internal.services ORDER BY service_id"
_SERVICE_ID = re.compile(r"^[A-Za-z0-9_-]+$")
AUTHORITY = ("osv", "ghsa", "cna")
TRUST = {"osv": 0.95, "ghsa": 0.9, "cna": 0.8, "nvd": 0.7}
VerdictName = Literal["affected", "not_affected", "uncertain"]


class DraftVerdict(BaseModel):
    case_id: str
    verdict: VerdictName
    basis: list[str]
    method: Literal["range_eval", "text_llm", "memory"] = "range_eval"
    confidence: float
    source: str = "combined"
    service_id: str = ""
    package: str = ""
    version: str = ""
    vuln_id: str = ""


class Conflict(BaseModel):
    case_id: str
    field: str
    values_by_source: dict[str, str]
    severity: Literal["blocking", "informational"]


class MatchResult(BaseModel):
    verdicts: list[DraftVerdict] = Field(default_factory=list)
    conflicts: list[Conflict] = Field(default_factory=list)


def load_candidates(settings: Settings | None = None) -> SqlResult:
    """Read `v_candidate_matches` one service at a time.

    Each page is `WHERE service_id = '…'`. A page whose row count reaches
    the limit is refused: that cut would otherwise look like a full result.
    The query does not compare version strings. `1.0` and `1.0.0` are the
    same version, and `version_eval` decides that in Python.
    """
    services = run_sql(SERVICE_SQL, settings=settings)
    if services.truncated:
        raise ResultTruncated("service list reached the row limit; refusing to continue")
    pages: list[SqlResult] = []
    for row in services.rows:
        service_id = row.get("service_id") or ""
        if not _SERVICE_ID.fullmatch(service_id):
            raise RuntimeError(f"service_id {service_id!r} is not safe to interpolate")
        page = run_sql(
            "SELECT * FROM sibyl.v_candidate_matches WHERE service_id = '" + service_id + "'",
            settings=settings,
            limit=CANDIDATE_PAGE_LIMIT,
        )
        if page.truncated:
            raise ResultTruncated(
                f"{service_id} returned {len(page.rows)} rows, the limit {CANDIDATE_PAGE_LIMIT}"
            )
        pages.append(page)
    return SqlResult(
        statement="\n".join([services.statement, *[page.statement for page in pages]]),
        rows=[row for page in pages for row in page.rows],
        milliseconds=services.milliseconds + sum(page.milliseconds for page in pages),
        truncated=False,
    )


def match(rows: Sequence[Mapping[str, str]]) -> MatchResult:
    """One combined draft per service, component version, and vulnerability.

    Also returns one draft per source and a Conflict when those sources
    disagree about this exact version.
    """
    grouped: dict[tuple, list[Mapping[str, str]]] = defaultdict(list)
    for row in rows:
        vuln = _text(row.get("cve_id")) or _text(row.get("vuln_id")) or ""
        key = (
            _text(row.get("service_id")) or "",
            _text(row.get("purl")) or "",
            _text(row.get("version")) or "",
            vuln,
        )
        grouped[key].append(row)
    verdicts: list[DraftVerdict] = []
    conflicts: list[Conflict] = []
    for key, group in grouped.items():
        case_verdicts, case_conflicts = _case(key, group)
        verdicts.extend(case_verdicts)
        conflicts.extend(case_conflicts)
    return MatchResult(verdicts=verdicts, conflicts=conflicts)


def _case(key: tuple[str, str, str, str], rows: list[Mapping[str, str]]) -> tuple[list[DraftVerdict], list[Conflict]]:
    service_id, purl, version, vuln_id = key
    case_id = f"case:{service_id}:{purl}:{vuln_id}"
    ecosystem = _text(rows[0].get("ecosystem")) or ""
    package = _text(rows[0].get("package")) or ""
    by_source: dict[str, list[Mapping[str, str]]] = defaultdict(list)
    for row in rows:
        by_source[_source_key(row)].append(row)
    per_source: dict[str, dict] = {}
    verdicts: list[DraftVerdict] = []
    for source, source_rows in sorted(by_source.items()):
        decision = _source_decision(ecosystem, version, source_rows)
        per_source[source] = decision
        verdicts.append(
            _verdict(
                case_id,
                decision["verdict"],
                decision["basis"],
                TRUST.get(source, 0.5) if decision["verdict"] != "uncertain" else 0.5,
                source,
                service_id,
                package,
                version,
                vuln_id,
            )
        )
    chosen = next(
        (
            source
            for source in AUTHORITY
            if source in per_source and per_source[source]["verdict"] in {"affected", "not_affected"}
        ),
        None,
    )
    if chosen is None:
        combined_name: VerdictName = "uncertain"
        confidence = 0.5
        basis: list[str] = []
    else:
        combined_name = per_source[chosen]["verdict"]
        confidence = TRUST.get(chosen, 0.5)
        basis = per_source[chosen]["basis"]
    conflict = _conflict(case_id, per_source)
    conflicts = [conflict] if conflict is not None else []
    if conflict is not None and conflict.severity == "blocking":
        confidence = round(confidence * 0.7, 4)
    verdicts.append(
        _verdict(case_id, combined_name, basis, confidence, "combined", service_id, package, version, vuln_id)
    )
    return verdicts, conflicts


def _source_decision(ecosystem: str, version: str, rows: list[Mapping[str, str]]) -> dict:
    ranges = [_range(row) for row in rows]
    decided = is_affected(ecosystem, version, ranges)
    withdrawn = any((_text(row.get("record_status")) or "") in {"withdrawn", "rejected"} for row in rows)
    if withdrawn:
        # A withdrawn or rejected record is never an affected verdict.
        verdict: VerdictName = "uncertain" if decided is None else "not_affected"
    elif decided is True:
        verdict = "affected"
    elif decided is False:
        verdict = "not_affected"
    else:
        verdict = "uncertain"
    basis = sorted({_text(row.get("record_id")) or "" for row in rows if _text(row.get("record_id"))})
    return {"verdict": verdict, "basis": basis, "withdrawn": withdrawn}


def _conflict(case_id: str, per_source: dict[str, dict]) -> Conflict | None:
    values = {
        source: info["verdict"]
        for source, info in per_source.items()
        if info["verdict"] in {"affected", "not_affected"}
    }
    if len(set(values.values())) < 2:
        return None
    authority_values = {source: verdict for source, verdict in values.items() if source in AUTHORITY}
    withdrawn = any(info["withdrawn"] for info in per_source.values())
    blocking = len(set(authority_values.values())) > 1 or (withdrawn and "affected" in values.values())
    return Conflict(
        case_id=case_id,
        field="withdrawn" if withdrawn else "affected_ranges",
        values_by_source=values,
        severity="blocking" if blocking else "informational",
    )


def _source_key(row: Mapping[str, str]) -> str:
    source = (_text(row.get("source")) or "").lower()
    range_type = (_text(row.get("range_type")) or "").upper()
    if source == "nvd" or range_type == "NVD_CPE":
        return "nvd"
    if source in {"cve_org", "cna"} or range_type == "CNA":
        return "cna"
    if source == "ghsa":
        return "ghsa"
    if source == "osv":
        return "osv"
    return source or "unknown"


def _range(row: Mapping[str, str]) -> dict:
    return {
        "introduced": _text(row.get("introduced")),
        "fixed": _text(row.get("fixed")),
        "last_affected": _text(row.get("last_affected")),
        "raw_range": _text(row.get("raw_range")),
        "range_type": _text(row.get("range_type")),
    }


def _verdict(
    case_id: str,
    verdict: VerdictName,
    basis: list[str],
    confidence: float,
    source: str,
    service_id: str,
    package: str,
    version: str,
    vuln_id: str,
) -> DraftVerdict:
    return DraftVerdict(
        case_id=case_id,
        verdict=verdict,
        basis=basis,
        method="range_eval",
        confidence=confidence,
        source=source,
        service_id=service_id,
        package=package,
        version=version,
        vuln_id=vuln_id,
    )


def _text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def case_id_for(row: Mapping[str, str]) -> str:
    service_id = _text(row.get("service_id")) or ""
    purl = _text(row.get("purl")) or ""
    vuln = _text(row.get("cve_id")) or _text(row.get("vuln_id")) or ""
    return f"case:{service_id}:{purl}:{vuln}"


class TextObservation(BaseModel):
    """A package named in advisory text, with no structured range."""

    case_id: str
    ecosystem: str
    package: str
    version: str
    vuln_id: str
    source: str
    record_id: str
    text: str
    service_id: str = ""


class ExtractedRange(BaseModel):
    quote: str = ""
    applies_to_package: bool = False
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    raw_range: str | None = None


class Evaluation(BaseModel):
    result: MatchResult
    flags: list[str] = Field(default_factory=list)


def evaluate(
    rows: Sequence[Mapping[str, str]],
    text_cases: Sequence[TextObservation] = (),
    *,
    llm: object | None = None,
    world: object | None = None,
    recheck_case_id: str | None = None,
) -> Evaluation:
    """Wrap `match`. Structured rows keep the deterministic verdict.

    Text cases are extracted on the deep lane. `version_eval` decides.
    A quote that is not in the source text does not become `affected`.
    Quarantined text is not sent to the model.
    """
    from sibyl.agents.prompts import load_prompt
    from sibyl.agents.scout import screen_advisory
    from sibyl.engines.messages import Conflict as ConflictMessage
    from sibyl.engines.messages import DraftVerdict as DraftMessage
    from sibyl.scoring import confidence, trust_weight

    selected = list(rows)
    texts = list(text_cases)
    if recheck_case_id:
        selected = [row for row in selected if case_id_for(row) == recheck_case_id]
        texts = [case for case in texts if case.case_id == recheck_case_id]
    outcome = match(selected)
    flags: list[str] = []
    structured_ids = {verdict.case_id for verdict in outcome.verdicts if verdict.source == "combined"}
    for case in texts:
        if case.case_id in structured_ids:
            continue
        draft, flag = _text_verdict(case, llm, load_prompt, screen_advisory, confidence, trust_weight)
        if flag:
            flags.append(flag)
        outcome.verdicts.append(draft)
    if world is not None:
        _write_match(world, outcome, DraftMessage, ConflictMessage)
    return Evaluation(result=outcome, flags=flags)


def _text_verdict(case: TextObservation, llm: object | None, load_prompt, screen_advisory, confidence, trust_weight):
    screened = screen_advisory(case.text)
    trust = trust_weight("cna" if case.source in {"cve_org", "cna"} else case.source)
    if screened.flagged or screened.text is None:
        return (
            DraftVerdict(
                case_id=case.case_id,
                verdict="uncertain",
                basis=[],
                method="range_eval",
                confidence=0.5,
                source="combined",
                service_id=case.service_id,
                package=case.package,
                version=case.version,
                vuln_id=case.vuln_id,
            ),
            f"injection:{case.case_id}",
        )
    if llm is None:
        raise RuntimeError(f"{case.case_id} has no structured range and no model was provided")
    import json

    extracted = llm.complete(
        "deep",
        [
            {"role": "system", "content": load_prompt("matcher")},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "package": case.package,
                        "version": case.version,
                        "ecosystem": case.ecosystem,
                        "vuln_id": case.vuln_id,
                        "text": screened.text,
                    }
                ),
            },
        ],
        ExtractedRange,
    )
    found = extracted.output
    quote_ok = bool(found.quote) and found.quote in screened.text
    score = confidence(trust=trust, llm_text=True).value
    if not quote_ok or not found.applies_to_package:
        verdict: VerdictName = "uncertain" if not quote_ok else "not_affected"
        basis = [case.record_id] if quote_ok else []
        return _draft(case, verdict, basis, score), None
    decided = is_affected(
        case.ecosystem,
        case.version,
        [
            {
                "introduced": found.introduced,
                "fixed": found.fixed,
                "last_affected": found.last_affected,
                "raw_range": found.raw_range,
                "range_type": "",
            }
        ],
    )
    if decided is True:
        name: VerdictName = "affected"
    elif decided is False:
        name = "not_affected"
    else:
        name = "uncertain"
    return _draft(case, name, [case.record_id], score), None


def _draft(case: TextObservation, verdict: VerdictName, basis: list[str], score: float) -> DraftVerdict:
    return DraftVerdict(
        case_id=case.case_id,
        verdict=verdict,
        basis=basis,
        method="text_llm",
        confidence=score,
        source="combined",
        service_id=case.service_id,
        package=case.package,
        version=case.version,
        vuln_id=case.vuln_id,
    )


def _write_match(world: object, outcome: MatchResult, draft_message, conflict_message) -> None:
    for verdict in outcome.verdicts:
        if verdict.source != "combined":
            continue
        world.draft_verdict(
            draft_message(
                case_id=verdict.case_id,
                verdict=verdict.verdict,
                basis=verdict.basis,
                method=verdict.method,
                confidence=verdict.confidence,
            )
        )
    for conflict in outcome.conflicts:
        world.conflict(conflict_message.model_validate(conflict.model_dump()))
