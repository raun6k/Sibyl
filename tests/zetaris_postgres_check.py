"""Prove Sibyl Postgres is readable through Zetaris.

Passes only when the probe rows, the in-source join, a cross-source join
against pokeapi, and a row inserted directly into Postgres are all visible
through POST /sql-editor/sqls/run. Prints each statement, its row count, and
milliseconds. Does not print secrets.

The freshness row is removed afterwards so the check can be run again.
"""

from __future__ import annotations

import sys
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from zetaris_rest import load_env, redact, rows_of, run_sql  # noqa: E402

FRESHNESS_ID = "freshness-probe"

SERVICES_SQL = (
    "SELECT service_id, name, team, internet_facing, criticality, data_class "
    "FROM acme_internal.services ORDER BY service_id"
)
AFFECTED_SQL = (
    "SELECT record_id, vuln_id, ecosystem, package, range_type, introduced, fixed, raw_range "
    "FROM evidence.affected ORDER BY record_id"
)
JOIN_SQL = (
    "SELECT c.component_id, c.name AS component_name, s.service_id, s.name AS service_name "
    "FROM acme_internal.components c "
    "JOIN acme_internal.sboms b ON c.sbom_id = b.sbom_id "
    "JOIN acme_internal.services s ON b.service_id = s.service_id "
    "ORDER BY c.component_id"
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


def expect_services(rows: list[dict[str, str]]) -> str | None:
    found = {(row.get("service_id"), row.get("name")) for row in rows}
    expected = {("checkout-api", "checkout-api"), ("reporting-worker", "reporting-worker")}
    if found != expected:
        return f"expected {sorted(expected)}, got {sorted(found)}"
    by_id = {row["service_id"]: row for row in rows}
    if by_id["checkout-api"].get("internet_facing") != "true":
        return "checkout-api internet_facing was not true"
    if by_id["reporting-worker"].get("internet_facing") != "false":
        return "reporting-worker internet_facing was not false"
    return None


def expect_affected(rows: list[dict[str, str]]) -> str | None:
    if len(rows) != 1:
        return f"expected 1 probe row, got {len(rows)}"
    row = rows[0]
    expected = {
        "record_id": "rec-probe-1",
        "vuln_id": "CVE-PROBE-0001",
        "ecosystem": "pypi",
        "package": "django",
        "range_type": "ECOSYSTEM",
        "raw_range": "<4.2.14",
    }
    for key, value in expected.items():
        if row.get(key) != value:
            return f"{key}={row.get(key)!r}, expected {value!r}"
    return None


def expect_join(rows: list[dict[str, str]]) -> str | None:
    found = {(row.get("component_id"), row.get("service_id")) for row in rows}
    expected = {
        ("comp-django", "checkout-api"),
        ("comp-pyyaml", "checkout-api"),
        ("comp-requests", "checkout-api"),
    }
    if found != expected:
        return f"expected {sorted(expected)}, got {sorted(found)}"
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
    try:
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
        except psycopg.Error as exc:
            fail("5 freshness cleanup", exc.__class__.__name__)
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
