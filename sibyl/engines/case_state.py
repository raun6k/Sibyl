"""Current case state as a Postgres table, for SQL and Zetaris.

`world.case_state` holds one row per case the World Model currently places
for a workspace: the latest placement of each case, while the latest run
that covered its service still placed it. It is rewritten after every
triage. Zetaris reads it through the `world` datasource and the USL table
`lightning.metastore.sibyl.inventory.case_state`.
"""

from __future__ import annotations

from typing import Any

import psycopg

from sibyl.config import Settings, load_settings
from sibyl.engines.world_model import ensure_world_schema

STATUS = {"ranked": "open", "needs_human": "needs_human", "closed": "closed"}


def case_rows(workspace_id: str, cases: list[dict[str, Any]]) -> list[tuple]:
    rows = []
    for item in cases:
        card = item.get("card") or {}
        placement = str(item.get("placement") or "needs_human")
        rows.append(
            (
                workspace_id,
                str(item.get("case_id") or ""),
                str(item.get("service_id") or ""),
                str(card.get("package") or ""),
                str(card.get("version") or ""),
                str(card.get("ecosystem") or ""),
                str(card.get("purl") or ""),
                str(card.get("vuln_id") or ""),
                str(card.get("verdict") or "uncertain"),
                placement,
                STATUS.get(placement, "needs_human"),
                float(card.get("score") or 0),
                float(card.get("confidence") or 0),
                str(card.get("resolution") or ""),
                bool(card.get("exploited")),
                float(card.get("epss_percentile") or 0),
                float(card.get("cvss") or 0),
                str(item.get("run_id") or ""),
                item.get("reused_from"),
            )
        )
    return rows


def project_case_state(world: Any, workspace_id: str, settings: Settings | None = None) -> int:
    """Rewrite the workspace's rows from the World Model. Returns the row count."""
    active = settings or load_settings()
    rows = case_rows(workspace_id, world.current_cases())
    with psycopg.connect(active.database_url) as conn:
        ensure_world_schema(conn)
        conn.execute("DELETE FROM world.case_state WHERE workspace_id = %s", (workspace_id,))
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO world.case_state
                    (workspace_id, case_id, service_id, package, version, ecosystem, purl, vuln_id, verdict, placement,
                     status, score, confidence, resolution, exploited, epss_percentile, cvss, run_id, reused_from)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                rows,
            )
    return len(rows)


OPEN_BY_TEAM = (
    "SELECT s.team AS team, count(*) AS open_affected "
    "FROM lightning.metastore.sibyl.inventory.case_state AS c "
    "JOIN lightning.metastore.sibyl.inventory.service AS s ON c.service_id = s.service_id "
    "WHERE c.workspace_id = '{workspace}' AND c.status = 'open' AND c.verdict = 'affected' "
    "GROUP BY s.team ORDER BY open_affected DESC"
)
