"""Source Mapper.

Authority per field is the matrix in `docs/project/data.md`. The model is
asked only for a name the tables do not join. NVD CPE is never the
authority for affected ranges.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence

from pydantic import BaseModel, Field

from sibyl.agents.matcher import case_id_for
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
