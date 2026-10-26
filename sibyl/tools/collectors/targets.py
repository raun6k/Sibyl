"""What a live ingest for one workspace asks the sources about.

Read from Postgres at ingest time, like the EPSS batch list: the packages
of the workspace's active services, and the CVE ids already tied to them.
"""

from __future__ import annotations

import re

import psycopg

from sibyl.config import Settings

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")

PACKAGES_SQL = """
SELECT DISTINCT components.ecosystem, components.name, components.version
FROM inventory.components AS components
JOIN inventory.sboms AS sboms ON components.sbom_id = sboms.sbom_id
JOIN inventory.services AS services ON sboms.service_id = services.service_id
WHERE services.status = 'active' AND services.workspace_id = %s
ORDER BY 1, 2, 3
"""

CVES_SQL = """
SELECT DISTINCT CASE WHEN affected.vuln_id LIKE 'CVE-%%' THEN affected.vuln_id ELSE aliases.alias_id END AS cve_id
FROM inventory.components AS components
JOIN inventory.sboms AS sboms ON components.sbom_id = sboms.sbom_id
JOIN inventory.services AS services ON sboms.service_id = services.service_id
JOIN evidence.affected AS affected
  ON affected.ecosystem = components.ecosystem AND affected.package = components.name
LEFT JOIN evidence.vuln_aliases AS aliases
  ON aliases.vuln_id = affected.vuln_id AND aliases.alias_id LIKE 'CVE-%%'
WHERE services.status = 'active' AND services.workspace_id = %s
"""


def workspace_packages(settings: Settings) -> list[tuple[str, str, str]]:
    if not settings.workspace_id or not settings.database_url:
        return []
    with psycopg.connect(settings.database_url) as conn:
        rows = conn.execute(PACKAGES_SQL, (settings.workspace_id,)).fetchall()
    return [(row[0], row[1], row[2]) for row in rows]


def workspace_cves(settings: Settings) -> list[str]:
    if not settings.workspace_id or not settings.database_url:
        return []
    with psycopg.connect(settings.database_url) as conn:
        rows = conn.execute(CVES_SQL, (settings.workspace_id,)).fetchall()
    return sorted({row[0] for row in rows if row[0] and _CVE.fullmatch(row[0])})
