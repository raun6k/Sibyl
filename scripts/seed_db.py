"""Apply the Sibyl Postgres schema and upsert Acme from the sample SBOMs.

Reads DATABASE_URL from the repo `.env`. Does not print the URL.
Running it twice leaves the same row counts. P1 probe rows are removed.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

import psycopg
from packageurl import PackageURL

from sibyl.tools.collectors.migrate import ensure_evidence_schema

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
SBOM_DIR = ROOT / "data" / "sample" / "sboms"

# team and data_class are chosen for the synthetic company. The rest is the
# Acme table in docs/project/data.md.
SERVICES = {
    "checkout-api": {
        "team": "payments",
        "internet_facing": True,
        "criticality": 1.0,
        "data_class": "cardholder",
    },
    "merchant-portal": {
        "team": "merchants",
        "internet_facing": True,
        "criticality": 0.8,
        "data_class": "merchant",
    },
    "reporting-worker": {
        "team": "data",
        "internet_facing": False,
        "criticality": 0.5,
        "data_class": "internal",
    },
    "internal-admin": {
        "team": "platform",
        "internet_facing": False,
        "criticality": 0.3,
        "data_class": "employee",
    },
}

PROBE_COMPONENTS = ("comp-django", "comp-requests", "comp-pyyaml")
PROBE_SBOM = "sbom-checkout-api"
PROBE_RECORD = "rec-probe-1"


def load_env(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def flatten(components: list | None) -> list[dict]:
    found: list[dict] = []
    for component in components or []:
        found.append(component)
        found.extend(flatten(component.get("components")))
    return found


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def direct_refs(document: dict) -> set[str]:
    metadata = document.get("metadata") or {}
    root = metadata.get("component") or {}
    root_ref = root.get("bom-ref")
    depends: set[str] = set()
    for entry in document.get("dependencies") or []:
        if root_ref and entry.get("ref") == root_ref:
            depends.update(entry.get("dependsOn") or [])
    return depends


def lockfile_of(document: dict, service: str) -> str:
    for prop in (document.get("metadata") or {}).get("properties") or []:
        if prop.get("name") == "cdx:bom:componentSrcFiles" and prop.get("value"):
            return str(prop["value"])
    return f"data/sample/internal/lockfiles/{service}"


def generated_at(document: dict) -> datetime:
    raw = ((document.get("metadata") or {}).get("timestamp")) or "2026-10-23T00:00:00Z"
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def load_acme() -> tuple[list[tuple], list[tuple], list[tuple]]:
    services: list[tuple] = []
    sboms: list[tuple] = []
    components: list[tuple] = []
    for service, meta in SERVICES.items():
        path = SBOM_DIR / f"{service}.cdx.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        spec = document.get("specVersion") or "1.6"
        bom_format = document.get("bomFormat") or "CycloneDX"
        sbom_id = service
        services.append(
            (
                service,
                service,
                meta["team"],
                meta["internet_facing"],
                meta["criticality"],
                meta["data_class"],
            )
        )
        sboms.append(
            (
                sbom_id,
                service,
                f"{bom_format}/{spec}",
                generated_at(document),
                lockfile_of(document, service),
            )
        )
        directs = direct_refs(document)
        seen: set[str] = set()
        for component in flatten(document.get("components")):
            purl = component.get("purl") or ""
            if not purl.startswith("pkg:") or purl in seen:
                continue
            seen.add(purl)
            parsed = PackageURL.from_string(purl)
            ecosystem = (parsed.type or "").lower()
            name = parsed.name or component.get("name") or ""
            if ecosystem == "pypi":
                name = pep503(name)
            version = parsed.version or component.get("version") or ""
            ref = component.get("bom-ref") or ""
            direct = ref in directs or purl in directs
            component_id = f"{sbom_id}|{purl}"
            components.append((component_id, sbom_id, purl, ecosystem, name, version, direct))
    return services, sboms, components


def clear_probe_rows(conn: psycopg.Connection) -> None:
    conn.execute("DELETE FROM evidence.affected WHERE record_id = %s", (PROBE_RECORD,))
    conn.execute("DELETE FROM evidence.source_records WHERE record_id = %s", (PROBE_RECORD,))
    conn.execute(
        "DELETE FROM acme_internal.components WHERE component_id = ANY(%s)",
        (list(PROBE_COMPONENTS),),
    )
    conn.execute("DELETE FROM acme_internal.sboms WHERE sbom_id = %s", (PROBE_SBOM,))


def main() -> int:
    env = load_env(ENV_PATH)
    url = env.get("DATABASE_URL", "")
    if not url:
        print("FAIL seed: missing DATABASE_URL", file=sys.stderr)
        return 1
    services, sboms, components = load_acme()
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    try:
        with psycopg.connect(url) as conn:
            conn.execute(sql)
            ensure_evidence_schema(conn)
            clear_probe_rows(conn)
            with conn.cursor() as cur:
                cur.executemany(
                    """
                    INSERT INTO acme_internal.services
                        (service_id, name, team, internet_facing, criticality, data_class)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (service_id) DO UPDATE SET
                        name = EXCLUDED.name,
                        team = EXCLUDED.team,
                        internet_facing = EXCLUDED.internet_facing,
                        criticality = EXCLUDED.criticality,
                        data_class = EXCLUDED.data_class
                    """,
                    services,
                )
                cur.executemany(
                    """
                    INSERT INTO acme_internal.sboms
                        (sbom_id, service_id, format, generated_at, source_lockfile)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (sbom_id) DO UPDATE SET
                        service_id = EXCLUDED.service_id,
                        format = EXCLUDED.format,
                        generated_at = EXCLUDED.generated_at,
                        source_lockfile = EXCLUDED.source_lockfile
                    """,
                    sboms,
                )
                cur.executemany(
                    """
                    INSERT INTO acme_internal.components
                        (component_id, sbom_id, purl, ecosystem, name, version, direct)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (component_id) DO UPDATE SET
                        sbom_id = EXCLUDED.sbom_id,
                        purl = EXCLUDED.purl,
                        ecosystem = EXCLUDED.ecosystem,
                        name = EXCLUDED.name,
                        version = EXCLUDED.version,
                        direct = EXCLUDED.direct
                    """,
                    components,
                )
            kept = [row[2] for row in components]
            conn.execute(
                """
                DELETE FROM acme_internal.components
                WHERE sbom_id = ANY(%s) AND NOT (purl = ANY(%s))
                """,
                (list(SERVICES), kept),
            )
            service_count = conn.execute("SELECT count(*) FROM acme_internal.services").fetchone()[0]
            sbom_count = conn.execute("SELECT count(*) FROM acme_internal.sboms").fetchone()[0]
            component_count = conn.execute("SELECT count(*) FROM acme_internal.components").fetchone()[0]
            direct_count = conn.execute(
                "SELECT count(*) FROM acme_internal.components WHERE direct"
            ).fetchone()[0]
            records = conn.execute("SELECT count(*) FROM evidence.source_records").fetchone()[0]
            affected = conn.execute("SELECT count(*) FROM evidence.affected").fetchone()[0]
            per_service = conn.execute(
                """
                SELECT b.service_id, count(*), count(*) FILTER (WHERE c.direct)
                FROM acme_internal.components c
                JOIN acme_internal.sboms b ON c.sbom_id = b.sbom_id
                GROUP BY b.service_id
                ORDER BY b.service_id
                """
            ).fetchall()
    except psycopg.Error as exc:
        print(f"FAIL seed: {exc.__class__.__name__}", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"FAIL seed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1
    print(
        "seeded"
        f" acme_internal.services={service_count}"
        f" sboms={sbom_count}"
        f" components={component_count}"
        f" direct={direct_count}"
        f" evidence.source_records={records}"
        f" affected={affected}"
    )
    for service_id, count, directs in per_service:
        print(f"  {service_id}: components={count} direct={directs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
