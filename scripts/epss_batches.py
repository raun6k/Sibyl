"""EPSS REST tables built from the CVEs that join an Acme component.

`v_candidate_matches` left-joins `v_epss` once. When the matched set is
larger than 100 ids, that view is one UNION ALL of `epss_batch_000`,
`epss_batch_001`, and so on. FIRST accepts at most 100 ids on `?cve=`.
The ids are read from Postgres, the same join the view uses, because this
runs at setup time and not through Zetaris.
"""

from __future__ import annotations

import re

import psycopg

BATCH_SIZE = 100
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Same component × affected × source-record × CVE-alias join as
# sibyl.v_candidate_matches, without the one-CVE-per-range ranking.
# Every CVE that join can produce is listed, not only the row_number winner.
MATCHED_CVE_SQL = """
SELECT DISTINCT cve_id
FROM (
  SELECT CASE
    WHEN affected.vuln_id LIKE 'CVE-%' THEN affected.vuln_id
    ELSE vuln_aliases.alias_id
  END AS cve_id
  FROM acme_internal.components AS components
  JOIN acme_internal.sboms AS sboms
    ON components.sbom_id = sboms.sbom_id
  JOIN acme_internal.services AS services
    ON sboms.service_id = services.service_id
  JOIN evidence.affected AS affected
    ON affected.ecosystem = components.ecosystem
   AND affected.package = components.name
  JOIN evidence.source_records AS source_records
    ON source_records.record_id = affected.record_id
  LEFT JOIN evidence.vuln_aliases AS vuln_aliases
    ON vuln_aliases.vuln_id = affected.vuln_id
   AND vuln_aliases.alias_id LIKE 'CVE-%'
) matched
WHERE cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
ORDER BY cve_id
"""


def load_matched_cves(database_url: str) -> list[str]:
    if not database_url:
        raise RuntimeError("DATABASE_URL is empty")
    with psycopg.connect(database_url) as conn:
        rows = conn.execute(MATCHED_CVE_SQL).fetchall()
    return [row[0] for row in rows]


def chunk_cves(cves: list[str], size: int = BATCH_SIZE) -> list[list[str]]:
    """Split a CVE list into batches of at most `size`, preserving order."""
    if size < 1:
        raise ValueError("batch size must be at least 1")
    ordered: list[str] = []
    seen: set[str] = set()
    for cve in cves:
        if cve in seen:
            continue
        if not CVE_RE.fullmatch(cve):
            raise ValueError(f"refusing CVE id {cve!r}")
        seen.add(cve)
        ordered.append(cve)
    if not ordered:
        raise ValueError("no matched CVE ids")
    return [ordered[index : index + size] for index in range(0, len(ordered), size)]


def table_name(index: int) -> str:
    return f"epss_batch_{index:03d}"


def expand_creates(template: str, cves: list[str]) -> list[str]:
    """One CREATE per batch. The template names `epss_batch_000` and `{{EPSS_CVES}}`."""
    if "{{EPSS_CVES}}" not in template:
        raise ValueError("EPSS template has no {{EPSS_CVES}} placeholder")
    statements: list[str] = []
    for index, group in enumerate(chunk_cves(cves)):
        statement = template.replace("epss_batch_000", table_name(index), 1)
        statement = statement.replace("{{EPSS_CVES}}", ",".join(group))
        statements.append(statement)
    return statements


def union_body(batch_count: int) -> str:
    """SELECT bodies for `v_epss`. Two or more batches are one UNION ALL."""
    if batch_count < 1:
        raise ValueError("v_epss needs at least one EPSS batch")
    parts = []
    for index in range(batch_count):
        parts.append(
            "SELECT\n"
            "  item.cve AS cve_id,\n"
            "  CAST(item.epss AS DOUBLE) AS epss,\n"
            "  CAST(item.percentile AS DOUBLE) AS percentile\n"
            f"FROM sibyl_public.{table_name(index)}\n"
            "LATERAL VIEW explode(data) AS item"
        )
    return "\nUNION ALL\n".join(parts)


def drop_statements(batch_count: int) -> list[str]:
    """Drop the views that reference EPSS, the legacy table, and batch tables.

    A later apply recreates `v_epss` and `v_candidate_matches`. Extra batch
    names cover a previous run that had more batches than this one.
    """
    statements = [
        "DROP SCHEMASTORE VIEW v_candidate_matches FROM sibyl",
        "DROP SCHEMASTORE VIEW v_epss FROM sibyl_feeds",
        "DROP LIGHTNING DATABASE TABLE sibyl_public.epss_batch",
    ]
    for index in range(max(batch_count, 1) + 4):
        statements.append(f"DROP LIGHTNING DATABASE TABLE sibyl_public.{table_name(index)}")
    return statements


def cache_statements(batch_count: int) -> list[str]:
    return [f"CACHE TABLE sibyl_public.{table_name(index)}" for index in range(batch_count)]
