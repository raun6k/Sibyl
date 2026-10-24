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
from sibyl.tools.collectors.osv import query_index
from sibyl.tools.zetaris import ResultTruncated, run_sql

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
    osv_listed: Mapping[str, set[str]] | None = None,
) -> list[MappedCase]:
    """Build one source map per case. `disabled` and `degraded` are source names.

    `osv_listed` maps a purl to the OSV ids the query batch returned. A purl
    that is present and does not list this CVE gets an `osv_query` claim.
    """
    off = {name.lower() for name in disabled or ()}
    weak = {name.lower() for name in degraded or ()}
    grouped: dict[str, list[Mapping[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[case_id_for(row)].append(row)
    alias_rows = list(aliases)
    mapped: list[MappedCase] = []
    for case_id, group in grouped.items():
        item = _one(case_id, group, alias_rows, off, weak)
        if osv_listed is not None:
            _note_osv_silence(item, group, alias_rows, osv_listed)
        if world is not None:
            _write(world, item)
        mapped.append(item)
    return mapped


def _note_osv_silence(item: MappedCase, group: list[Mapping[str, str]], aliases: list[Mapping[str, str]], listed: Mapping[str, set[str]]) -> None:
    purl = next((str(row.get("purl") or "") for row in group if row.get("purl")), "")
    vuln = next((str(row.get("cve_id") or row.get("vuln_id") or "") for row in group), "")
    if not purl or not vuln or not osv_not_listed(purl, vuln, listed, aliases):
        return
    item.claims.append(
        Claim(
            case_id=item.case_id,
            source="osv",
            field="osv_query",
            value="queried this purl and did not list the CVE",
            raw_ref=purl,
            retrieved_at="",
            source_status="active",
        )
    )


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
WHERE source = '{source}' AND source_id LIKE 'CVE-{year}-%'
"""
def find_text_cases(settings: Settings | None = None) -> list[TextObservation]:
    """Open uncertain cases for packages named in CVE.org or NVD text.

    Reads go through `run_sql`. A truncated page is refused. Affected rows
    are limited to Acme packages, so a cut-off catalogue cannot look like a
    package with no structured range.
    """
    active = settings or load_settings()
    components = _complete(_COMPONENTS, active, "components")
    affected = _affected_for_components(components, active)
    aliases = _complete(_ALIASES, active, "aliases")
    prose = _prose(active)
    return text_cases_from(components, affected, aliases, prose)


def _complete(sql: str, settings: Settings, label: str) -> list[dict[str, str]]:
    loaded = run_sql(sql, settings=settings, limit=10000)
    if loaded.truncated:
        raise ResultTruncated(f"{label} returned {len(loaded.rows)} rows, the limit 10000")
    return loaded.rows


def _affected_for_components(components: list[dict[str, str]], settings: Settings) -> list[dict[str, str]]:
    by_ecosystem: dict[str, list[str]] = defaultdict(list)
    for row in components:
        ecosystem = (row.get("ecosystem") or "").lower()
        name = row.get("name") or ""
        if not name:
            continue
        if not re.fullmatch(r"[a-z0-9]+", ecosystem) or not re.fullmatch(r"[@A-Za-z0-9._+/-]+", name):
            raise RuntimeError(f"refusing package {ecosystem}:{name}")
        if name not in by_ecosystem[ecosystem]:
            by_ecosystem[ecosystem].append(name)
    rows: list[dict[str, str]] = []
    for ecosystem, names in by_ecosystem.items():
        for start in range(0, len(names), 20):
            rows.extend(_affected_page(ecosystem, names[start : start + 20], settings))
    return rows


def _affected_page(ecosystem: str, names: list[str], settings: Settings) -> list[dict[str, str]]:
    """Distinct package rows. A full page is continued, not treated as complete."""
    quoted = ", ".join(f"'{name}'" for name in names)
    rows: list[dict[str, str]] = []
    last_vuln = ""
    last_package = ""
    while True:
        page = ""
        if last_vuln:
            page = f" AND (vuln_id > '{last_vuln}' OR (vuln_id = '{last_vuln}' AND package > '{last_package}'))"
        loaded = run_sql(
            "SELECT DISTINCT vuln_id, ecosystem, package FROM evidence.affected "
            f"WHERE ecosystem = '{ecosystem}' AND package IN ({quoted}){page} "
            "ORDER BY vuln_id, package",
            settings=settings,
            limit=10000,
        )
        if not loaded.rows:
            return rows
        rows.extend(loaded.rows)
        if not loaded.truncated:
            return rows
        nxt_vuln = loaded.rows[-1].get("vuln_id") or ""
        nxt_package = loaded.rows[-1].get("package") or ""
        if nxt_vuln == last_vuln and nxt_package == last_package:
            raise ResultTruncated(f"affected {ecosystem} page did not advance")
        last_vuln, last_package = nxt_vuln, nxt_package


def _prose(settings: Settings) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for source in ("cve_org", "nvd"):
        for year in range(1999, 2028):
            rows.extend(
                _complete(
                    _PROSE.format(source=source, year=year),
                    settings,
                    f"{source} CVE-{year}",
                )
            )
    return rows


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
                affected=_cna_affected(record.get("raw_json") or "") if source == "cve_org" else [],
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
    if loaded.truncated:
        raise ResultTruncated(
            f"aliases returned {len(loaded.rows)} rows, the limit; refusing a cut-off alias list"
        )
    return loaded.rows


def osv_listed(settings: Settings | None = None) -> dict[str, set[str]]:
    """Purl to OSV ids returned for that purl. Absent purls were not queried."""
    active = settings or load_settings()
    return query_index(active.snapshot_path() / "osv")


def osv_not_listed(purl: str, vuln_id: str, listed: Mapping[str, set[str]], aliases: Sequence[Mapping[str, str]]) -> bool:
    """True when this purl was queried and neither the id nor an alias came back."""
    if purl not in listed:
        return False
    returned = set(listed[purl])
    if vuln_id in returned:
        return False
    linked = set(returned)
    for row in aliases:
        left = str(row.get("vuln_id") or "")
        right = str(row.get("alias_id") or "")
        if left in returned or right in returned:
            linked.add(left)
            linked.add(right)
    return vuln_id not in linked


def _cna_affected(raw: str) -> list[dict]:
    try:
        body = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    cna = ((body.get("containers") or {}).get("cna") or {}) if isinstance(body, dict) else {}
    kept: list[dict] = []
    for item in cna.get("affected") or []:
        if not isinstance(item, dict):
            continue
        versions = []
        for version in item.get("versions") or []:
            if not isinstance(version, dict):
                continue
            versions.append(
                {
                    key: version.get(key)
                    for key in ("status", "version", "lessThan", "lessThanOrEqual")
                    if version.get(key) not in (None, "")
                }
            )
        kept.append(
            {
                "product": item.get("product") or item.get("packageName") or "",
                "defaultStatus": item.get("defaultStatus") or "",
                "versions": versions,
            }
        )
    return kept


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
