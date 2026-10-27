"""One case in the World Model.

The Mapper writes a case's facts as claims: the advisory ranges per source
record, the description, OSV's answer for the purl, the sibling packages
with structured rows, the component, and the priority inputs (KEV, EPSS,
CVSS, the service's exposure and criticality). The Matcher writes its draft
verdicts and conflicts per round. The Critic, the Prioritiser and the
Reporter read the case back from `world.case(case_id)` and build their view
from that projection, not from the bundle the collection stage produced.

A case's verdict fingerprint is a hash of the claims that decide the
verdict (ranges, description, OSV silence, siblings, component and its
inventory edge) plus the run context (disabled sources, a human
resolution, the trust table, the critic switch). Priority inputs are not in
it: a new EPSS score re-scores a case, it does not re-triage it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, Field

from sibyl.agents.critic import CaseView, Side
from sibyl.agents.matcher import Conflict, DraftVerdict, MatchResult, case_id_for, cna_posture
from sibyl.engines.messages import Claim
from sibyl.engines.messages import Conflict as ConflictMessage
from sibyl.engines.messages import DraftVerdict as DraftMessage
from sibyl.scoring import confidence as confidence_of
from sibyl.scoring import trust_weight

# Bump when the triage logic changes in a way that should re-decide reused verdicts.
LOGIC_VERSION = "p10.1"
VERDICT_FIELDS = ("affected_range", "description", "osv_query", "siblings", "component")
PRIORITY_FIELDS = ("exploited", "epss_percentile", "severity_cvss", "service_facts")
# Row cells that are not advisory facts: feed scores and service facts are priority claims of their own.
_ROW_VOLATILE = {
    "team",
    "service_name",
    "internet_facing",
    "criticality",
    "data_class",
    "kev_date_added",
    "kev_due_date",
    "kev_ransomware",
    "euvd_id",
    "euvd_epss",
    "epss",
    "epss_percentile",
    "retrieved_at",
}


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
    # Other packages in the same service with structured rows for this vulnerability.
    siblings: list[str] = Field(default_factory=list)


# Writes ---------------------------------------------------------------------


def case_claims(case: Bundle) -> list[Claim]:
    """The Mapper's claims for one case. The last one lists the keys this run stated."""
    claims: list[Claim] = []
    records: dict[tuple[str, str], list[dict[str, str]]] = {}
    for row in case.rows:
        if case_of(row) != case.case_id:
            continue
        key = (source_of(row), cell(row, "record_id"))
        records.setdefault(key, []).append(
            {name: str(value) for name, value in row.items() if name not in _ROW_VOLATILE and value is not None}
        )
    for (source, record_id), rows in records.items():
        statuses = [item.get("record_status") or "active" for item in rows]
        status = next((value for value in statuses if value in {"withdrawn", "rejected"}), statuses[0])
        claims.append(_claim(case, source, "affected_range", rows, record_id, status))
    claims.append(
        _claim(
            case,
            "inventory",
            "component",
            {
                "package": case.package,
                "version": case.version,
                "vuln_id": case.vuln_id,
                "ecosystem": case.ecosystem,
                "purl": case.purl,
            },
            case.purl or case.package,
        )
    )
    if case.description or case.record_id:
        claims.append(_claim(case, "advisory", "description", {"text": case.description, "record_id": case.record_id}))
    claims.append(_claim(case, "osv", "osv_query", bool(case.osv_not_listed)))
    claims.append(_claim(case, "inventory", "siblings", sorted(case.siblings)))
    claims.append(_claim(case, "kev", "exploited", bool(case.exploited)))
    claims.append(_claim(case, "epss", "epss_percentile", float(case.epss_percentile)))
    claims.append(
        _claim(case, "severity", "severity_cvss", {"score": float(case.cvss), "source": case.cvss_source, "version": case.cvss_version})
    )
    claims.append(
        _claim(case, "inventory", "service_facts", {"internet_facing": bool(case.internet_facing), "criticality": float(case.criticality)})
    )
    keys = sorted(_key(item.source, item.field, item.raw_ref) for item in claims)
    claims.append(_claim(case, "sibyl", "manifest", keys))
    return claims


def _claim(case: Bundle, source: str, field: str, value: Any, raw_ref: str = "", status: str = "active") -> Claim:
    return Claim(
        case_id=case.case_id,
        source=source,
        field=field,
        value=value,
        raw_ref=raw_ref,
        retrieved_at="",
        source_status=status,
    )


def text_draft(case: Bundle, run_id: str) -> DraftMessage | None:
    """The Matcher's reading of a text-only description, made during collection."""
    if not (case.method or case.quote or case.applies_to_package is not None or case.text_bound or case.verdict or case.related_affected):
        return None
    method = case.method if case.method in {"text_llm", "quarantine", "memory"} else "range_eval"
    verdict = case.verdict if case.verdict in {"affected", "not_affected", "uncertain"} else "uncertain"
    return DraftMessage(
        case_id=case.case_id,
        verdict=verdict,  # type: ignore[arg-type]
        basis=[case.record_id] if case.record_id else [],
        method=method,  # type: ignore[arg-type]
        confidence=0.0,
        run_id=run_id,
        source="text",
        round=0,
        quote=case.quote,
        applies_to_package=case.applies_to_package,
        text_bound=case.text_bound,
        related_affected=case.related_affected,
    )


def outcome_messages(outcome: MatchResult, case_id: str, run_id: str, round: int) -> list[tuple[str, BaseModel]]:
    """One Matcher round for one case: every draft (each source, then combined) and conflict."""
    messages: list[tuple[str, BaseModel]] = []
    for verdict in outcome.verdicts:
        if verdict.case_id != case_id:
            continue
        messages.append(
            (
                "draft_verdict",
                DraftMessage(
                    case_id=case_id,
                    verdict=verdict.verdict,
                    basis=list(verdict.basis),
                    method=verdict.method,
                    confidence=verdict.confidence,
                    run_id=run_id,
                    source=verdict.source,
                    round=round,
                ),
            )
        )
    for conflict in outcome.conflicts:
        if conflict.case_id != case_id:
            continue
        messages.append(
            (
                "conflict",
                ConflictMessage(
                    case_id=case_id,
                    field=conflict.field,
                    values_by_source=dict(conflict.values_by_source),
                    severity=conflict.severity,
                    run_id=run_id,
                    round=round,
                ),
            )
        )
    return messages


# Reads ----------------------------------------------------------------------


def current_claims(projection: dict[str, Any]) -> list[dict[str, Any]]:
    """Claims this case stated the last time the Mapper wrote it, in write order."""
    claims = [item for item in projection.get("claims") or [] if isinstance(item, dict)]
    manifest = next((item for item in claims if item.get("field") == "manifest" and item.get("source") == "sibyl"), None)
    if manifest is None:
        return [item for item in claims if item.get("field") != "manifest"]
    wanted = set(manifest.get("value") or [])
    return [item for item in claims if _key(item.get("source"), item.get("field"), item.get("raw_ref")) in wanted]


def bundle_from_case(projection: dict[str, Any], *, disabled: list[str] | tuple[str, ...] = ()) -> Bundle:
    """The case as the World Model holds it: claims, plus the Matcher's text reading for this run."""
    claims = current_claims(projection)
    by_field: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, str]] = []
    for item in claims:
        field = str(item.get("field") or "")
        if field == "affected_range":
            rows.extend(dict(row) for row in item.get("value") or [] if isinstance(row, dict))
        else:
            by_field.setdefault(field, item)
    component = _value(by_field, "component", {})
    description = _value(by_field, "description", {})
    severity = _value(by_field, "severity_cvss", {})
    facts = _value(by_field, "service_facts", {})
    text = next(
        (item for item in reversed(projection.get("draft_verdicts") or []) if item.get("source") == "text"),
        None,
    )
    case = Bundle(
        case_id=str(projection.get("case_id") or ""),
        rows=rows,
        package=str(component.get("package") or ""),
        version=str(component.get("version") or ""),
        vuln_id=str(component.get("vuln_id") or ""),
        ecosystem=str(component.get("ecosystem") or ""),
        purl=str(component.get("purl") or ""),
        description=str(description.get("text") or ""),
        record_id=str(description.get("record_id") or ""),
        osv_not_listed=bool(_value(by_field, "osv_query", False)),
        siblings=[str(name) for name in _value(by_field, "siblings", []) or []],
        exploited=bool(_value(by_field, "exploited", False)),
        epss_percentile=float(_value(by_field, "epss_percentile", 0) or 0),
        cvss=float(severity.get("score") or 0),
        cvss_source=str(severity.get("source") or ""),
        cvss_version=str(severity.get("version") or ""),
        internet_facing=bool(facts.get("internet_facing")),
        criticality=float(facts.get("criticality") or 0),
        disabled=list(disabled),
    )
    if text is not None:
        case.method = str(text.get("method") or "")
        case.verdict = str(text.get("verdict") or "")
        case.quote = str(text.get("quote") or "")
        case.applies_to_package = text.get("applies_to_package")
        case.text_bound = str(text.get("text_bound") or "")
        case.related_affected = text.get("related_affected")
    return case


def outcome_from_case(projection: dict[str, Any]) -> MatchResult:
    """The Matcher's latest round for this run, as a MatchResult."""
    drafts = [item for item in projection.get("draft_verdicts") or [] if item.get("source") != "text"]
    if not drafts:
        return MatchResult()
    latest = max(int(item.get("round") or 0) for item in drafts)
    verdicts = [
        DraftVerdict(
            case_id=str(item.get("case_id") or ""),
            verdict=item.get("verdict") or "uncertain",
            basis=list(item.get("basis") or []),
            method=item.get("method") or "range_eval",
            confidence=float(item.get("confidence") or 0),
            source=str(item.get("source") or "combined"),
        )
        for item in drafts
        if int(item.get("round") or 0) == latest
    ]
    conflicts = [
        Conflict(
            case_id=str(item.get("case_id") or ""),
            field=str(item.get("field") or ""),
            values_by_source=dict(item.get("values_by_source") or {}),
            severity=item.get("severity") or "informational",
        )
        for item in projection.get("conflicts") or []
        if int(item.get("round") or 0) == latest
    ]
    return MatchResult(verdicts=verdicts, conflicts=conflicts)


def case_view(projection: dict[str, Any], *, disabled: list[str] | tuple[str, ...] = ()) -> CaseView:
    """What the Critic and the Prioritiser judge, built from `world.case()`."""
    case = bundle_from_case(projection, disabled=disabled)
    view = view_of(case, outcome_from_case(projection))
    view.prior_verdict, view.prior_run = _prior(projection)
    return view


def _prior(projection: dict[str, Any]) -> tuple[str, str]:
    prior = projection.get("prior")
    if not isinstance(prior, dict):
        return "", ""
    card = prior.get("card") if isinstance(prior.get("card"), dict) else {}
    return str(card.get("verdict") or ""), str(prior.get("reused_from") or prior.get("run_id") or "")


def view_of(case: Bundle, outcome: MatchResult) -> CaseView:
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
        if case_of(row) != case.case_id:
            continue
        source = source_of(row)
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
                introduced=cell(row, "introduced"),
                fixed=cell(row, "fixed"),
                last_affected=cell(row, "last_affected"),
                status=cell(row, "record_status") or "active",
            )
        )
    # Keep one side per source. A withdrawn status is not hidden by an earlier row.
    unique: dict[str, Side] = {}
    for side in sides:
        current_side = unique.get(side.source)
        if current_side is None or side.status in {"withdrawn", "rejected"}:
            unique[side.source] = side
    package, version, vuln = identity(case, combined)
    ecosystem = case.ecosystem or (cell(case.rows[0], "ecosystem") if case.rows else "")
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


def extra(case: Bundle, outcome: MatchResult, positions: list[dict[str, str]]) -> dict[str, Any]:
    """The report card fields that are not placement: identity, records, conflicts, positions, inputs."""
    combined = next(
        (verdict for verdict in outcome.verdicts if verdict.case_id == case.case_id and verdict.source == "combined"),
        None,
    )
    package, version, vuln = identity(case, combined)
    record_ids = sorted({cell(row, "record_id") for row in case.rows if cell(row, "record_id")})
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
        "confidence_factors": confidence_factors(case, combined),
        "method": case.method or (combined.method if combined is not None else ""),
        "exploited": case.exploited,
        "ecosystem": case.ecosystem,
        "purl": case.purl,
        "cvss": case.cvss,
        "cvss_source": case.cvss_source,
        "cvss_version": case.cvss_version,
        "epss_percentile": case.epss_percentile,
    }


def confidence_factors(case: Bundle, combined: Any) -> list[dict[str, Any]]:
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


def positions(outcome: MatchResult, case: Bundle) -> list[dict[str, str]]:
    """One position per source: verdict, record status, and a version bound.

    A withdrawn GHSA row keeps status `withdrawn`. A CNA "through 3.0.3"
    range keeps that bound, so a needs-human case can show all three.
    """
    status_by_source: dict[str, str] = {}
    bound_by_source: dict[str, str] = {}
    for row in case.rows:
        if case_of(row) != case.case_id:
            continue
        source = source_of(row)
        status = cell(row, "record_status") or "active"
        if source not in status_by_source or status in {"withdrawn", "rejected"}:
            status_by_source[source] = status
        bound = cell(row, "last_affected") or cell(row, "fixed")
        if bound and source not in bound_by_source:
            bound_by_source[source] = bound
    found: list[dict[str, str]] = []
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
        found.append(item)
    _add_text_position(found, case)
    if case.osv_not_listed and not any(item.get("source") == "osv" for item in found):
        found.append({"source": "osv", "verdict": "not_listed"})
    return found


def _add_text_position(found: list[dict[str, str]], case: Bundle) -> None:
    """A text-only case has no range row. The human still needs the quote."""
    if case.method not in {"text_llm", "quarantine"} and not case.quote:
        return
    source = advisory_source(case.record_id)
    if any(item.get("source") == source and item.get("quote") for item in found):
        return
    if any(item.get("source") == source and item.get("verdict") in {"affected", "not_affected"} for item in found):
        for item in found:
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
    found.append(item)


def advisory_source(record_id: str) -> str:
    raw = record_id.split(":", 1)[0].lower() if record_id else ""
    if raw in {"cve_org", "cna"}:
        return "cna"
    if raw.startswith("nvd"):
        return "nvd"
    return raw or "cna"


def identity(case: Bundle, combined: Any) -> tuple[str, str, str]:
    if case.package:
        return case.package, case.version, case.vuln_id
    if combined is not None and getattr(combined, "package", ""):
        return combined.package, combined.version, combined.vuln_id
    if case.rows:
        row = case.rows[0]
        return cell(row, "package"), cell(row, "version"), cell(row, "cve_id") or cell(row, "vuln_id")
    return "", "", ""


def case_of(row: dict[str, str]) -> str:
    return case_id_for(row)


def source_of(row: dict[str, str]) -> str:
    from sibyl.agents.matcher import _source_key

    return _source_key(row)


def cell(row: dict[str, str], key: str) -> str:
    return str(row.get(key) or "").strip()


# Incremental ------------------------------------------------------------------


def fingerprint(projection: dict[str, Any], context: dict[str, Any]) -> str:
    """Hash of what decides the verdict. Row order does not count; a changed range does."""
    items = []
    for item in current_claims(projection):
        if item.get("field") not in VERDICT_FIELDS:
            continue
        value = item.get("value")
        if item.get("field") == "affected_range" and isinstance(value, list):
            value = sorted(json.dumps(row, sort_keys=True) for row in value)
        items.append(json.dumps({"s": item.get("source"), "f": item.get("field"), "r": item.get("raw_ref"), "v": value}, sort_keys=True))
    body = json.dumps({"claims": sorted(items), "context": context, "logic": LOGIC_VERSION}, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:20]


def priority_inputs(projection: dict[str, Any]) -> dict[str, Any]:
    """The current KEV, EPSS, CVSS and service facts, for re-scoring a reused case."""
    case = bundle_from_case(projection)
    return {
        "exploited": case.exploited,
        "epss_percentile": case.epss_percentile,
        "cvss": case.cvss,
        "cvss_source": case.cvss_source,
        "cvss_version": case.cvss_version,
        "internet_facing": case.internet_facing,
        "criticality": case.criticality,
    }


def service_of(case_id: str) -> str:
    parts = case_id.split(":")
    return parts[1] if len(parts) > 1 else ""


def _key(source: Any, field: Any, raw_ref: Any) -> str:
    return f"{source or ''}|{field or ''}|{raw_ref or ''}"


def _value(by_field: dict[str, dict[str, Any]], field: str, default: Any) -> Any:
    item = by_field.get(field)
    if item is None:
        return default
    value = item.get("value")
    return default if value is None else value
