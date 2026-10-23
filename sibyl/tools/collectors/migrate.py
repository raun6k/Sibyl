"""Bring an existing evidence schema in line with scripts/schema.sql.

CREATE TABLE IF NOT EXISTS does not add columns or change primary keys, and
the P1 database is already created. `range_index` distinguishes multiple
ranges for one package. The severity key includes the CVSS version so v3 and
v4 from the same source can both be stored.
"""

from __future__ import annotations

import psycopg


def ensure_evidence_schema(conn: psycopg.Connection) -> None:
    conn.execute(
        """
        ALTER TABLE evidence.affected
        ADD COLUMN IF NOT EXISTS range_index integer NOT NULL DEFAULT 0
        """
    )
    definition = _primary_key(conn, "evidence.affected")
    if definition and "range_index" not in definition[1]:
        conn.execute(f'ALTER TABLE evidence.affected DROP CONSTRAINT "{definition[0]}"')
        conn.execute(
            """
            ALTER TABLE evidence.affected
            ADD PRIMARY KEY (record_id, vuln_id, ecosystem, package, range_type, range_index)
            """
        )
    conn.execute("UPDATE evidence.severities SET version = '' WHERE version IS NULL")
    conn.execute("ALTER TABLE evidence.severities ALTER COLUMN version SET DEFAULT ''")
    conn.execute("ALTER TABLE evidence.severities ALTER COLUMN version SET NOT NULL")
    severity_key = _primary_key(conn, "evidence.severities")
    if severity_key and "version" not in severity_key[1]:
        conn.execute(f'ALTER TABLE evidence.severities DROP CONSTRAINT "{severity_key[0]}"')
        conn.execute(
            """
            ALTER TABLE evidence.severities
            ADD PRIMARY KEY (record_id, vuln_id, source, version)
            """
        )


def _primary_key(conn: psycopg.Connection, table: str) -> tuple[str, str] | None:
    row = conn.execute(
        """
        SELECT con.conname, pg_get_constraintdef(con.oid)
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
        WHERE con.contype = 'p' AND nsp.nspname || '.' || rel.relname = %s
        """,
        (table,),
    ).fetchone()
    if row is None:
        return None
    return str(row[0]), str(row[1])
