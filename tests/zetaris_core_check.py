"""Prove one Zetaris query joins Acme, evidence, and KEV.

Ingests the frozen fixtures, caches the REST-backed views, and checks
sibyl.v_candidate_matches. Prints each read, its row count, and milliseconds.
A row inserted into evidence.affected must show up on the next query. That
probe row is deleted afterwards. Does not print secrets.

CACHE TABLE is not a read, so it goes through the setup client. The selects
go through sibyl.tools.zetaris.run_sql.
"""

from __future__ import annotations

import sys
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from zetaris_rest import load_env, redact, run_sql as setup_sql  # noqa: E402

from sibyl.config import Settings, load_settings  # noqa: E402
from sibyl.tools.collectors import ingest  # noqa: E402
from sibyl.tools.zetaris import run_sql  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "snapshots"
PROBE_RECORD = "rec-zetaris-core-probe"
SERVICES = ("checkout-api", "internal-admin", "merchant-portal", "reporting-worker")

COUNTS_SQL = (
    "SELECT service_id, count(*) AS rows "
    "FROM sibyl.v_candidate_matches "
    "GROUP BY service_id ORDER BY service_id"
)
KEV_SQL = (
    "SELECT service_id, package, vuln_id, cve_id, kev_date_added "
    "FROM sibyl.v_candidate_matches "
    "WHERE cve_id = 'CVE-2023-4863' AND kev_date_added IS NOT NULL "
    "LIMIT 1"
)
PROBE_SQL = (
    "SELECT service_id, package, vuln_id, record_id "
    "FROM sibyl.v_candidate_matches "
    f"WHERE record_id = '{PROBE_RECORD}'"
)
CACHE_SQL = (
    "CACHE TABLE sibyl_public.kev_catalog",
    "CACHE TABLE sibyl_public.euvd_exploited",
    "CACHE TABLE sibyl_public.epss_batch",
    "CACHE TABLE sibyl_feeds.v_kev",
    "CACHE TABLE sibyl_feeds.v_euvd_exploited",
    "CACHE TABLE sibyl_feeds.v_epss",
)


def fail(step: str, detail: str) -> None:
    print(f"FAIL {step}: {detail}", file=sys.stderr)


def collapse(sql: str) -> str:
    return " ".join(sql.split())


def fixture_settings(loaded: Settings) -> Settings:
    return Settings(
        database_url=loaded.database_url,
        sample_mode=True,
        snapshot_dir=str(FIXTURES),
        contact_email=loaded.contact_email,
        zetaris_rest_url=loaded.zetaris_rest_url,
        zetaris_org_id=loaded.zetaris_org_id,
        zetaris_api_key=loaded.zetaris_api_key,
    )


def cache_views(env: dict[str, str]) -> str | None:
    secret = env.get("ZETARIS_API_KEY", "")
    email = env.get("CONTACT_EMAIL", "")
    for sql in CACHE_SQL:
        result = setup_sql(env, sql, timeout=180)
        print(f"cache  ms={result['ms']}  {sql}")
        if result["error"]:
            return redact(result["error"], secret, email)[:500]
    return None


def insert_probe(url: str) -> None:
    with psycopg.connect(url) as conn:
        conn.execute("DELETE FROM evidence.affected WHERE record_id = %s", (PROBE_RECORD,))
        conn.execute("DELETE FROM evidence.source_records WHERE record_id = %s", (PROBE_RECORD,))
        conn.execute(
            """
            INSERT INTO evidence.source_records
                (record_id, source, source_id, retrieved_at, status, raw_json, content_hash)
            VALUES (%s, 'osv', 'PROBE-CORE', '2026-10-23 00:00:00+00', 'active', %s::jsonb, 'probe-core')
            """,
            (PROBE_RECORD, '{"probe": true}'),
        )
        conn.execute(
            """
            INSERT INTO evidence.affected (
                record_id, vuln_id, ecosystem, package, range_type,
                introduced, fixed, last_affected, raw_range, range_index
            )
            VALUES (%s, 'CVE-PROBE-CORE', 'pypi', 'django', 'ECOSYSTEM', '0', '9.9.9', NULL, '<9.9.9', 0)
            """,
            (PROBE_RECORD,),
        )


def delete_probe(url: str) -> None:
    with psycopg.connect(url) as conn:
        conn.execute("DELETE FROM evidence.affected WHERE record_id = %s", (PROBE_RECORD,))
        conn.execute("DELETE FROM evidence.source_records WHERE record_id = %s", (PROBE_RECORD,))


def main() -> int:
    loaded = load_settings()
    env = load_env()
    if not loaded.database_url:
        fail("setup", "missing DATABASE_URL")
        return 1
    active = fixture_settings(loaded)
    reports = ingest(settings=active)
    for report in reports:
        print(report.summary())
    if any(report.status not in {"ok", "degraded"} or report.errors for report in reports):
        fail("ingest", "a fixture source did not load cleanly")
        return 1

    error = cache_views(env)
    if error:
        fail("cache", error)
        return 1

    failed = False
    try:
        counts = run_sql(COUNTS_SQL, settings=active)
        print(f"counts  rows={len(counts.rows)}  ms={counts.milliseconds}")
        print(f"  SQL: {counts.statement}")
        found = {row.get("service_id"): row.get("rows") for row in counts.rows}
        for service in SERVICES:
            print(f"  {service}: {found.get(service, '0')}")
        if set(found) != set(SERVICES):
            fail("counts", f"expected {SERVICES}, got {sorted(found)}")
            failed = True
        elif any(int(found[service] or "0") <= 0 for service in SERVICES):
            fail("counts", f"a service has no rows: {found}")
            failed = True

        kev = run_sql(KEV_SQL, settings=active)
        print(f"kev  rows={len(kev.rows)}  ms={kev.milliseconds}")
        print(f"  SQL: {kev.statement}")
        if kev.rows:
            print(f"  {kev.rows[0]}")
        if not kev.rows or kev.rows[0].get("cve_id") != "CVE-2023-4863":
            fail("kev", "no candidate row joined CISA KEV")
            failed = True
        elif not kev.rows[0].get("kev_date_added"):
            fail("kev", "KEV date was empty")
            failed = True

        insert_probe(loaded.database_url)
        probe = run_sql(PROBE_SQL, settings=active)
        print(f"probe  rows={len(probe.rows)}  ms={probe.milliseconds}")
        print(f"  SQL: {probe.statement}")
        if probe.rows:
            print(f"  {probe.rows[0]}")
        if len(probe.rows) != 1 or probe.rows[0].get("package") != "django":
            fail("probe", f"inserted affected row was not visible: {probe.rows}")
            failed = True
        elif probe.rows[0].get("service_id") != "checkout-api":
            fail("probe", f"service_id={probe.rows[0].get('service_id')}")
            failed = True
    except (RuntimeError, psycopg.Error) as exc:
        fail("query", exc.__class__.__name__ if isinstance(exc, psycopg.Error) else str(exc))
        failed = True
    finally:
        try:
            delete_probe(loaded.database_url)
        except psycopg.Error as exc:
            fail("cleanup", exc.__class__.__name__)
            failed = True

    if failed:
        return 1
    print("PASS zetaris core")
    return 0


if __name__ == "__main__":
    sys.exit(main())
