"""Upsert normalised records into the evidence schema.

Unchanged records are not rewritten. A second ingest of the same bodies
reports 0 new, 0 changed, and leaves every row count as it was.
"""

from __future__ import annotations

import psycopg
from psycopg.types.json import Json

from sibyl.tools.collectors.base import NormalizedRecord, SourceBatch, SourceReport
from sibyl.tools.collectors.normalize import content_hash


def write_batch(conn: psycopg.Connection, batch: SourceBatch) -> SourceReport:
    if batch.status == "disabled":
        return SourceReport(batch.source, "disabled", 0, 0, 0, list(batch.errors), batch.git_ranges_skipped)
    hashes = {
        record.record_id: content_hash(record.body)
        for record in batch.records
    }
    existing: dict[str, str] = {}
    if hashes:
        rows = conn.execute(
            "SELECT record_id, content_hash FROM evidence.source_records WHERE record_id = ANY(%s)",
            (list(hashes),),
        ).fetchall()
        existing = {row[0]: row[1] for row in rows}
    fresh: list[NormalizedRecord] = []
    new = changed = unchanged = 0
    for record in batch.records:
        digest = hashes[record.record_id]
        if record.record_id not in existing:
            new += 1
            fresh.append(record)
        elif existing[record.record_id] != digest:
            changed += 1
            fresh.append(record)
        else:
            unchanged += 1
    if fresh:
        _upsert_records(conn, fresh, hashes)
        _replace_children(conn, batch)
    return SourceReport(
        batch.source,
        batch.status,
        new,
        changed,
        unchanged,
        list(batch.errors),
        batch.git_ranges_skipped,
    )


def _upsert_records(conn: psycopg.Connection, records: list[NormalizedRecord], hashes: dict[str, str]) -> None:
    rows = [
        (
            record.record_id,
            record.source,
            record.source_id,
            record.retrieved_at,
            record.status,
            Json(record.body),
            hashes[record.record_id],
        )
        for record in records
    ]
    _executemany(
        conn,
        """
        INSERT INTO evidence.source_records
            (record_id, source, source_id, retrieved_at, status, raw_json, content_hash)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (record_id) DO UPDATE SET
            source = EXCLUDED.source,
            source_id = EXCLUDED.source_id,
            retrieved_at = EXCLUDED.retrieved_at,
            status = EXCLUDED.status,
            raw_json = EXCLUDED.raw_json,
            content_hash = EXCLUDED.content_hash
        """,
        rows,
    )


def _replace_children(conn: psycopg.Connection, batch: SourceBatch) -> None:
    record_ids = [record.record_id for record in batch.records]
    if record_ids:
        conn.execute("DELETE FROM evidence.affected WHERE record_id = ANY(%s)", (record_ids,))
        conn.execute("DELETE FROM evidence.severities WHERE record_id = ANY(%s)", (record_ids,))
    conn.execute("DELETE FROM evidence.vuln_aliases WHERE source = %s", (batch.source,))
    affected = []
    severities = []
    aliases: set[tuple[str, str, str]] = set()
    for record in batch.records:
        for row in record.affected:
            affected.append(
                (
                    record.record_id,
                    row.vuln_id,
                    row.ecosystem,
                    row.package,
                    row.range_type,
                    row.introduced,
                    row.fixed,
                    row.last_affected,
                    row.raw_range,
                    row.range_index,
                )
            )
        for row in record.severities:
            severities.append(
                (
                    record.record_id,
                    row.vuln_id,
                    row.source,
                    row.vector,
                    row.score,
                    row.version or "",
                )
            )
        for vuln_id, alias_id in record.aliases:
            aliases.add((vuln_id, alias_id, batch.source))
    _executemany(
        conn,
        """
        INSERT INTO evidence.affected (
            record_id, vuln_id, ecosystem, package, range_type,
            introduced, fixed, last_affected, raw_range, range_index
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        affected,
    )
    _executemany(
        conn,
        """
        INSERT INTO evidence.severities
            (record_id, vuln_id, source, vector, score, version)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        severities,
    )
    _executemany(
        conn,
        """
        INSERT INTO evidence.vuln_aliases (vuln_id, alias_id, source)
        VALUES (%s, %s, %s)
        ON CONFLICT (vuln_id, alias_id, source) DO NOTHING
        """,
        list(aliases),
    )


def _executemany(conn: psycopg.Connection, sql: str, rows: list[tuple]) -> None:
    if not rows:
        return
    with conn.cursor() as cur:
        for start in range(0, len(rows), 500):
            cur.executemany(sql, rows[start : start + 500])
