"""Source Mapper.

Authority per field is the matrix in `docs/project/data.md`. The model is
asked only for a name the tables do not join. NVD CPE is never the
authority for affected ranges.

Text-only cases come from Zetaris. A CVE.org or NVD description that names
an Acme package, with no structured range for that package, opens a case.
The case starts uncertain. `append-field@1.0.0` is one of those cases.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence

from pydantic import BaseModel, Field

from sibyl.agents.matcher import TextObservation, case_id_for
from sibyl.agents.prompts import load_prompt
from sibyl.config import Settings, load_settings
from sibyl.engines.messages import AliasLink, Claim, SourceMap
from sibyl.engines.world_model import WorldModelClient
from sibyl.llm.client import LLMClient
from sibyl.scoring import trust_weight
from sibyl.tools.zetaris import run_sql

# Field, then sources in authority order. NVD CPE is not an authority for ranges.
AUTHORITY: dict[str, tuple[str, ...]] = {
    "affected_ranges": ("osv", "ghsa", "cna"),
    "fixed_version": ("ghsa", "osv", "cna"),
    "aliases": ("osv", "euvd", "ghsa"),
    "severity_cvss": ("cna", "cisa-adp", "nvd"),
    "exploited": ("kev", "euvd", "cisa-adp"),
    "epss": ("epss", "euvd"),
    "withdrawn": ("osv", "ghsa"),
}

_SOURCE_NAMES = {"osv": "osv", "ghsa": "ghsa", "nvd": "nvd", "cve_org": "cna", "cna": "cna", "euvd": "euvd"}


class ProductMatch(BaseModel):
    purl: str | None = None
    package: str | None = None
    confidence: float = 0
    quote: str = ""


class MappedCase(BaseModel):
    case_id: str
    source_map: SourceMap
    claims: list[Claim] = Field(default_factory=list)
    aliases: list[AliasLink] = Field(default_factory=list)
    ids_by_source: dict[str, list[str]] = Field(default_factory=dict)


def map_cases(
    rows: Sequence[Mapping[str, str]],
    aliases: Sequence[Mapping[str, str]] = (),
    *,
    disabled: set[str] | None = None,
    degraded: set[str] | None = None,
    world: WorldModelClient | None = None,
) -> list[MappedCase]:
    """Build one source map per case. `disabled` and `degraded` are source names."""
    off = {name.lower() for name in disabled or ()}
    weak = {name.lower() for name in degraded or ()}
    grouped: dict[str, list[Mapping[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[case_id_for(row)].append(row)
    alias_rows = list(aliases)
    mapped: list[MappedCase] = []
    for case_id, group in grouped.items():
        item = _one(case_id, group, alias_rows, off, weak)
        if world is not None:
            _write(world, item)
        mapped.append(item)
    return mapped


def map_unknown_product(
    name: str,
    candidates: Sequence[Mapping[str, str]],
    llm: LLMClient,
) -> ProductMatch:
    """Fast lane, and only for a name the tables did not join."""
    guess = llm.complete(
        "fast",
        [
            {"role": "system", "content": load_prompt("mapper")},
            {
                "role": "user",
                "content": _candidate_payload(name, candidates),
            },
        ],
        ProductMatch,
    )
    match = guess.output
    known = {row.get("purl") for row in candidates}
    if match.purl and match.purl not in known:
        return ProductMatch(purl=None, package=None, confidence=0, quote=match.quote)
    return match


_COMPONENTS = """
SELECT services.service_id, components.purl, components.ecosystem, components.name, components.version
FROM acme_internal.components
JOIN acme_internal.sboms ON components.sbom_id = sboms.sbom_id
JOIN acme_internal.services ON sboms.service_id = services.service_id
"""
_AFFECTED = "SELECT vuln_id, ecosystem, package FROM evidence.affected"
_ALIASES = "SELECT vuln_id, alias_id, source FROM evidence.vuln_aliases"
_PROSE = """
SELECT record_id, source, source_id, status, raw_json
FROM evidence.source_records
WHERE source = 'cve_org' OR source = 'nvd'
"""
def find_text_cases(settings: Settings | None = None) -> list[TextObservation]:
    """Open uncertain cases for packages named in CVE.org or NVD text.

    Reads go through `run_sql`. A package that already has a structured
    range for that vulnerability is not opened again.
    """
    active = settings or load_settings()
    components = run_sql(_COMPONENTS, settings=active).rows
    affected = run_sql(_AFFECTED, settings=active).rows
    aliases = run_sql(_ALIASES, settings=active).rows
    prose = run_sql(_PROSE, settings=active, timeout=180).rows
    return text_cases_from(components, affected, aliases, prose)


def text_cases_from(
    components: Sequence[Mapping[str, str]],
    affected: Sequence[Mapping[str, str]],
    aliases: Sequence[Mapping[str, str]],
    records: Sequence[Mapping[str, str]],
) -> list[TextObservation]:
    covered = _covered(affected, aliases)
    found: dict[str, TextObservation] = {}
    ordered = sorted(records, key=lambda row: 0 if row.get("source") == "cve_org" else 1)
    for record in ordered:
        source = _text(record.get("source")) or ""
        vuln_id = _text(record.get("source_id")) or ""
        record_id = _text(record.get("record_id")) or ""
        if not vuln_id or not record_id:
            continue
        prose = english_description(source, record.get("raw_json") or "")
        if not prose:
            continue
        for component in components:
            name = _text(component.get("name")) or ""
            ecosystem = (_text(component.get("ecosystem")) or "").lower()
            if not _mentioned(prose, name):
                continue
            if (ecosystem, name, vuln_id) in covered:
                continue
            service_id = _text(component.get("service_id")) or ""
            purl = _text(component.get("purl")) or ""
            version = _text(component.get("version")) or ""
            case_id = f"case:{service_id}:{purl}:{vuln_id}"
            if case_id in found:
                continue
            found[case_id] = TextObservation(
                case_id=case_id,
                ecosystem=ecosystem,
                package=name,
                version=version,
                vuln_id=vuln_id,
                source=source,
                record_id=record_id,
                text=prose,
                service_id=service_id,
            )
    return list(found.values())


def english_description(source: str, raw: str) -> str:
    """English description text from a CVE.org or NVD body. Empty if it is not JSON."""
    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return ""
    chunks: list[str] = []
    if source == "nvd":
        vulnerabilities = body.get("vulnerabilities") if isinstance(body, dict) else None
        cve = vulnerabilities[0].get("cve", {}) if isinstance(vulnerabilities, list) and vulnerabilities else {}
        chunks.extend(_english(cve.get("descriptions")))
    elif isinstance(body, dict):
        containers = body.get("containers") if isinstance(body.get("containers"), dict) else {}
        cna = containers.get("cna") if isinstance(containers.get("cna"), dict) else {}
        chunks.extend(_english(cna.get("descriptions")))
        for adp in containers.get("adp") or []:
            if isinstance(adp, dict):
                chunks.extend(_english(adp.get("descriptions")))
    return "\n".join(chunk for chunk in chunks if chunk)


def _english(items: object) -> list[str]:
    if not isinstance(items, list):
        return []
    found: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("lang") not in (None, "", "en"):
            continue
        value = item.get("value")
        if isinstance(value, str) and value.strip():
            found.append(value.strip())
    return found


def _mentioned(prose: str, name: str) -> bool:
    """A package token, not an English word and not a slash-joined MIME type.

    `form-data` inside `multipart/form-data` does not count. `moment` inside
    "at any moment" does not count. A hyphen or a digit in the name counts,
    and so does "package <name>" or a version sitting against the name.
    """
    if len(name) < 3:
        return False
    pattern = rf"(?<![A-Za-z0-9_./-]){re.escape(name)}(?![A-Za-z0-9_./-])"
    for match in re.finditer(pattern, prose):
        if _package_context(prose, match.start(), match.end(), name):
            return True
    return False


def _package_context(prose: str, start: int, end: int, name: str) -> bool:
    if "-" in name or any(character.isdigit() for character in name):
        return True
    before = prose[max(0, start - 16) : start].lower().rstrip()
    after = prose[end : end + 24].lower()
    if before.endswith("package"):
        return True
    return re.match(r"\s*(version|before|through|prior|v?\d)", after) is not None


def _covered(
    affected: Sequence[Mapping[str, str]],
    aliases: Sequence[Mapping[str, str]],
) -> set[tuple[str, str, str]]:
    parent: dict[str, str] = {}

    def find(value: str) -> str:
        parent.setdefault(value, value)
        if parent[value] != value:
            parent[value] = find(parent[value])
        return parent[value]

    def union(left: str, right: str) -> None:
        parent[find(left)] = find(right)

    ids: set[str] = set()
    for row in aliases:
        vuln = _text(row.get("vuln_id")) or ""
        alias = _text(row.get("alias_id")) or ""
        if vuln and alias:
            union(vuln, alias)
            ids.add(vuln)
            ids.add(alias)
    groups: dict[str, set[str]] = defaultdict(set)
    for value in ids:
        groups[find(value)].add(value)
    family = {value: groups[find(value)] for value in ids}
    covered: set[tuple[str, str, str]] = set()
    for row in affected:
        package = _text(row.get("package")) or ""
        ecosystem = (_text(row.get("ecosystem")) or "").lower()
        vuln = _text(row.get("vuln_id")) or ""
        if not package or not vuln:
            continue
        for linked in family.get(vuln, {vuln}):
            covered.add((ecosystem, package, linked))
    return covered


def load_alias_rows(settings: Settings | None = None) -> list[dict[str, str]]:
    loaded = run_sql(
        "SELECT vuln_id, alias_id, source FROM evidence.vuln_aliases",
        settings=settings or load_settings(),
    )
    return loaded.rows


def _one(
    case_id: str,
    rows: list[Mapping[str, str]],
    aliases: list[Mapping[str, str]],
    disabled: set[str],
    degraded: set[str],
) -> MappedCase:
    present = {_source_name(row) for row in rows}
    ids_by_source: dict[str, set[str]] = defaultdict(set)
    claims: list[Claim] = []
    for row in rows:
        source = _source_name(row)
        for key in ("vuln_id", "cve_id", "record_id"):
            value = _text(row.get(key))
            if value:
                ids_by_source[source].add(value)
        record_id = _text(row.get("record_id")) or ""
        if not record_id:
            continue
        claims.append(
            Claim(
                case_id=case_id,
                source=source,
                field="affected_ranges",
                value=_range_value(row),
                raw_ref=record_id,
                retrieved_at=_text(row.get("retrieved_at")) or "",
                source_status=_text(row.get("record_status")) or "active",
            )
        )
    alias_links = _alias_links(case_id, ids_by_source, aliases)
    for link in alias_links:
        ids_by_source.setdefault(_source_name({"source": link.source}), set()).add(link.alias_id)
        ids_by_source[link.source].add(link.vuln_id)
    fields: dict[str, str] = {}
    gaps: list[str] = []
    for field, order in AUTHORITY.items():
        chosen = None
        for source in order:
            if source in disabled:
                gaps.append(f"{source} disabled for {field}")
                continue
            if source in degraded:
                gaps.append(f"{source} degraded for {field}")
                continue
            if source in present or source in ids_by_source:
                chosen = source
                break
        if chosen is None:
            gaps.append(f"no authority for {field}")
        else:
            fields[field] = chosen
    return MappedCase(
        case_id=case_id,
        source_map=SourceMap(case_id=case_id, fields=fields, gaps=_unique(gaps)),
        claims=claims,
        aliases=alias_links,
        ids_by_source={source: sorted(values) for source, values in ids_by_source.items()},
    )


def _alias_links(
    case_id: str,
    ids_by_source: dict[str, set[str]],
    aliases: list[Mapping[str, str]],
) -> list[AliasLink]:
    known = {value for values in ids_by_source.values() for value in values}
    links: list[AliasLink] = []
    seen: set[tuple[str, str]] = set()
    for row in aliases:
        vuln = _text(row.get("vuln_id")) or ""
        alias = _text(row.get("alias_id")) or ""
        if not vuln or not alias or vuln == alias:
            continue
        if vuln not in known and alias not in known and vuln not in case_id and alias not in case_id:
            continue
        pair = (vuln, alias)
        if pair in seen:
            continue
        seen.add(pair)
        source = _source_name(row)
        links.append(
            AliasLink(
                vuln_id=vuln,
                alias_id=alias,
                source=source,
                confidence=trust_weight(source),
            )
        )
    return links


def _write(world: WorldModelClient, item: MappedCase) -> None:
    for claim in item.claims:
        world.claim(claim)
    for link in item.aliases:
        world.alias_link(link)
    world.source_map(item.source_map)


def _source_name(row: Mapping[str, str]) -> str:
    raw = (_text(row.get("source")) or "").lower()
    return _SOURCE_NAMES.get(raw, raw or "unknown")


def _range_value(row: Mapping[str, str]) -> str:
    parts = [
        f"{name}={_text(row.get(name))}"
        for name in ("introduced", "fixed", "last_affected", "raw_range")
        if _text(row.get(name))
    ]
    return ", ".join(parts)


def _candidate_payload(name: str, candidates: Sequence[Mapping[str, str]]) -> str:
    import json

    body = {
        "name": name,
        "candidates": [
            {"purl": row.get("purl", ""), "package": row.get("package", ""), "ecosystem": row.get("ecosystem", "")}
            for row in candidates
        ],
    }
    return json.dumps(body)


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
