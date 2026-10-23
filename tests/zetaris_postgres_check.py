"""Prove Sibyl Postgres is readable through Zetaris.

Passes when the seeded Acme services, an affected row this check inserts
itself, the component join, a cross-source join against pokeapi, and a
service row inserted directly into Postgres are all visible through
POST /sql-editor/sqls/run. Prints each statement, its row count, and
milliseconds. Does not print secrets.

The probe rows are removed afterwards so the check can be run again.
"""

from __future__ import annotations

import sys
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from zetaris_rest import load_env, redact, rows_of, run_sql  # noqa: E402

FRESHNESS_ID = "freshness-probe"
PROBE_RECORD = "rec-zetaris-probe"
EXPECTED_COMPONENTS = 422

EXPECTED_SERVICES = {
    "checkout-api": ("payments", True, 1.0, "cardholder"),
    "merchant-portal": ("merchants", True, 0.8, "merchant"),
    "reporting-worker": ("data", False, 0.5, "internal"),
    "internal-admin": ("platform", False, 0.3, "employee"),
}

SERVICES_SQL = (
    "SELECT service_id, name, team, internet_facing, criticality, data_class "
    "FROM acme_internal.services ORDER BY service_id"
)
AFFECTED_SQL = (
    "SELECT record_id, vuln_id, ecosystem, package, range_type, introduced, fixed, raw_range "
    "FROM evidence.affected WHERE record_id = 'rec-zetaris-probe'"
)
JOIN_SQL = (
    "SELECT c.name AS component_name, c.version, c.direct, s.service_id "
    "FROM acme_internal.components c "
    "JOIN acme_internal.sboms b ON c.sbom_id = b.sbom_id "
    "JOIN acme_internal.services s ON b.service_id = s.service_id "
    "ORDER BY s.service_id, c.name"
)
FEDERATION_SQL = (
    "SELECT s.service_id, p.ability_name "
    "FROM acme_internal.services s "
    "CROSS JOIN pokeapi.pikachu_abilities_table p "
    "LIMIT 1"
)
FRESHNESS_SQL = (
    "SELECT service_id, name FROM acme_internal.services "
    f"WHERE service_id = '{FRESHNESS_ID}'"
)


def collapse(sql: str) -> str:
    return " ".join(sql.split())


def report(step: str, sql: str, row_count: int, ms: int) -> None:
    print(f"{step}  rows={row_count}  ms={ms}")
    print(f"  SQL: {collapse(sql)}")


def fail(step: str, detail: str) -> None:
    print(f"FAIL {step}: {detail}", file=sys.stderr)


def as_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    text = value.strip().lower()
    if text in {"true", "t", "1"}:
        return True
    if text in {"false", "f", "0"}:
        return False
    return None


def expect_services(rows: list[dict[str, str]]) -> str | None:
    by_id = {row.get("service_id"): row for row in rows}
    if set(by_id) != set(EXPECTED_SERVICES):
        return f"expected {sorted(EXPECTED_SERVICES)}, got {sorted(by_id)}"
    for service_id, (team, facing, criticality, data_class) in EXPECTED_SERVICES.items():
        row = by_id[service_id]
        if row.get("name") != service_id:
            return f"{service_id} name={row.get('name')!r}"
        if row.get("team") != team:
            return f"{service_id} team={row.get('team')!r}"
        if as_bool(row.get("internet_facing")) is not facing:
            return f"{service_id} internet_facing={row.get('internet_facing')!r}"
        if row.get("data_class") != data_class:
            return f"{service_id} data_class={row.get('data_class')!r}"
        try:
            got = float(row.get("criticality") or "nan")
        except ValueError:
            return f"{service_id} criticality={row.get('criticality')!r}"
        if abs(got - criticality) > 0.001:
            return f"{service_id} criticality={got}"
    return None


def expect_affected(rows: list[dict[str, str]]) -> str | None:
    if len(rows) != 1:
        return f"expected 1 probe row, got {len(rows)}"
    row = rows[0]
    expected = {
        "record_id": PROBE_RECORD,
        "vuln_id": "CVE-PROBE-0001",
        "ecosystem": "pypi",
        "package": "django",
        "range_type": "ECOSYSTEM",
        "introduced": "0",
        "fixed": "4.2.14",
        "raw_range": "<4.2.14",
    }
    for key, value in expected.items():
        if row.get(key) != value:
            return f"{key}={row.get(key)!r}, expected {value!r}"
    return None


def expect_join(rows: list[dict[str, str]]) -> str | None:
    if len(rows) != EXPECTED_COMPONENTS:
        return f"expected {EXPECTED_COMPONENTS} components, got {len(rows)}"
    django = [
        row
        for row in rows
        if row.get("service_id") == "checkout-api" and row.get("component_name") == "django"
    ]
    if len(django) != 1:
        return f"expected one checkout-api django row, got {len(django)}"
    if django[0].get("version") != "4.2.3":
        return f"django version={django[0].get('version')!r}"
    if as_bool(django[0].get("direct")) is not True:
        return f"django direct={django[0].get('direct')!r}"
    return None


def expect_federation(rows: list[dict[str, str]]) -> str | None:
    if len(rows) != 1:
        return f"expected 1 row, got {len(rows)}"
    row = rows[0]
    if row.get("service_id") not in {"checkout-api", "reporting-worker"}:
        return f"service_id={row.get('service_id')!r}"
    if not row.get("ability_name"):
        return "ability_name was empty"
    return None


def delete_freshness(url: str) -> None:
    with psycopg.connect(url) as conn:
        conn.execute(
            "DELETE FROM acme_internal.services WHERE service_id = %s",
            (FRESHNESS_ID,),
        )


def insert_affected_probe(url: str) -> None:
    with psycopg.connect(url) as conn:
        conn.execute("DELETE FROM evidence.affected WHERE record_id = %s", (PROBE_RECORD,))
        conn.execute("DELETE FROM evidence.source_records WHERE record_id = %s", (PROBE_RECORD,))
        conn.execute(
            """
            INSERT INTO evidence.source_records
                (record_id, source, source_id, retrieved_at, status, raw_json, content_hash)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s)
            """,
            (
                PROBE_RECORD,
                "osv",
                "PROBE-OSV-1",
                "2026-10-23 00:00:00+00",
                "active",
                '{"probe": true}',
                "probe-zetaris",
            ),
        )
        conn.execute(
            """
            INSERT INTO evidence.affected
                (record_id, vuln_id, ecosystem, package, range_type, introduced, fixed, last_affected, raw_range)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NULL, %s)
            """,
            (PROBE_RECORD, "CVE-PROBE-0001", "pypi", "django", "ECOSYSTEM", "0", "4.2.14", "<4.2.14"),
        )


def delete_affected_probe(url: str) -> None:
    with psycopg.connect(url) as conn:
        conn.execute("DELETE FROM evidence.affected WHERE record_id = %s", (PROBE_RECORD,))
        conn.execute("DELETE FROM evidence.source_records WHERE record_id = %s", (PROBE_RECORD,))


def insert_freshness(url: str) -> None:
    with psycopg.connect(url) as conn:
        conn.execute(
            """
            INSERT INTO acme_internal.services
                (service_id, name, team, internet_facing, criticality, data_class)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (FRESHNESS_ID, FRESHNESS_ID, "probe", False, 0.0, "probe"),
        )


def query(env: dict[str, str], sql: str) -> tuple[list[dict[str, str]], int, str | None]:
    result = run_sql(env, sql, timeout=90)
    if result["error"]:
        secret = env.get("ZETARIS_API_KEY", "")
        return [], result["ms"], redact(result["error"], secret)[:500]
    return rows_of(result["payload"]), result["ms"], None


def main() -> int:
    env = load_env()
    url = env.get("DATABASE_URL", "")
    if not url:
        fail("setup", "missing DATABASE_URL")
        return 1
    try:
        delete_freshness(url)
        delete_affected_probe(url)
        insert_affected_probe(url)
    except psycopg.Error as exc:
        fail("setup", exc.__class__.__name__)
        return 1

    checks = [
        ("1 services", SERVICES_SQL, expect_services),
        ("2 affected", AFFECTED_SQL, expect_affected),
        ("3 join", JOIN_SQL, expect_join),
        ("4 federation", FEDERATION_SQL, expect_federation),
    ]
    failed = False
    try:
        for step, sql, expect in checks:
            rows, ms, error = query(env, sql)
            report(step, sql, len(rows), ms)
            if error:
                fail(step, error)
                failed = True
                continue
            problem = expect(rows)
            if problem:
                fail(step, problem)
                failed = True

        try:
            insert_freshness(url)
        except psycopg.Error as exc:
            fail("5 freshness", exc.__class__.__name__)
            return 1
        rows, ms, error = query(env, FRESHNESS_SQL)
        report("5 freshness", FRESHNESS_SQL, len(rows), ms)
        if error:
            fail("5 freshness", error)
            failed = True
        elif len(rows) != 1 or rows[0].get("service_id") != FRESHNESS_ID:
            fail("5 freshness", f"inserted row was not visible, got {rows}")
            failed = True
            refreshed = try_refresh(env)
            if refreshed:
                print(f"  refresh: {refreshed}")
    finally:
        try:
            delete_freshness(url)
            delete_affected_probe(url)
        except psycopg.Error as exc:
            fail("cleanup", exc.__class__.__name__)
            failed = True

    if failed:
        return 1
    print("PASS zetaris postgres")
    return 0


def try_refresh(env: dict[str, str]) -> str:
    """Diagnostic only. Records whether a refresh command reveals the new row."""
    notes: list[str] = []
    for sql in (
        "UNCACHE DATASOURCE acme_internal",
        "REFRESH DATASOURCE TABLES FROM acme_internal",
    ):
        result = run_sql(env, sql, timeout=90)
        if result["error"]:
            notes.append(f"{sql.split()[0]} failed")
        else:
            notes.append(f"{sql} ok ms={result['ms']}")
    rows, ms, error = query(env, FRESHNESS_SQL)
    if error:
        notes.append("reread failed")
    else:
        visible = len(rows) == 1 and rows[0].get("service_id") == FRESHNESS_ID
        notes.append(f"reread rows={len(rows)} ms={ms} visible={visible}")
    return "; ".join(notes)


if __name__ == "__main__":
    sys.exit(main())
