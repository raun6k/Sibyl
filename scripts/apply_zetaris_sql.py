"""Fill Zetaris SQL placeholders from `.env` and run each statement.

The SQL file keeps host, port, user, password, and database as placeholders.
This script substitutes them and POSTs one statement at a time. It does not
print the API key or the database password.

Host defaults to host.docker.internal because the Zetaris query engine runs
in a container. Override with ZETARIS_PG_HOST and ZETARIS_PG_PORT when the
database is reached by another address, such as a shared Docker network.
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

import psycopg

from epss_batches import (
    cache_statements,
    chunk_cves,
    drop_statements,
    expand_creates,
    load_matched_cves,
    union_body,
)
from zetaris_rest import load_env, redact, run_sql, split_sql

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SQL = ROOT / "zetaris" / "sql" / "04_postgres.sql"
CORE_SQL = ROOT / "zetaris" / "sql" / "05_core_views.sql"

ALREADY_EXISTS = (
    "already exists",
    "already registered",
    "name exist",
    "datasource name exist",
)
MISSING_OBJECT = (
    "does not exist",
    "doesn't exist",
    "does not exists",
    "not found",
    "cannot be found",
    "can't be found",
    "no such",
    "unknown table",
    "table or view not found",
    "not exist",
)


def connection_parts(env: dict[str, str]) -> dict[str, str] | str:
    raw = env.get("DATABASE_URL", "")
    if not raw:
        return "missing DATABASE_URL"
    parsed = urlparse(raw)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname or not parsed.path.strip("/"):
        return "DATABASE_URL is not a postgres URL"
    if not parsed.username or parsed.password is None:
        return "DATABASE_URL is missing a user or password"
    return {
        "PG_HOST": env.get("ZETARIS_PG_HOST") or "host.docker.internal",
        "PG_PORT": env.get("ZETARIS_PG_PORT") or str(parsed.port or 5432),
        "PG_USER": unquote(parsed.username),
        "PG_PASSWORD": unquote(parsed.password),
        "PG_DATABASE": unquote(parsed.path.strip("/")),
        "CONTACT_EMAIL": env.get("CONTACT_EMAIL", "").strip(),
    }


def fill(sql: str, parts: dict[str, str]) -> str:
    filled = sql
    for key, value in parts.items():
        filled = filled.replace("{{" + key + "}}", value.replace('"', '\\"'))
    return filled


def first_line(sql: str) -> str:
    for line in sql.splitlines():
        text = line.strip()
        if text:
            return text
    return sql.strip()


def expand_statement(statement: str, cves: list[str] | None) -> list[str]:
    """Turn EPSS placeholders into one statement per batch."""
    if "{{EPSS_CVES}}" in statement:
        if not cves:
            raise RuntimeError("{{EPSS_CVES}} needs the matched CVE list")
        batches = chunk_cves(cves)
        # Drop first so a second apply replaces the URL instead of skipping
        # "already exists" and keeping the previous CVE list.
        return drop_statements(len(batches)) + expand_creates(statement, cves)
    if "{{EPSS_UNION}}" in statement:
        if not cves:
            raise RuntimeError("{{EPSS_UNION}} needs the matched CVE list")
        return [statement.replace("{{EPSS_UNION}}", union_body(len(chunk_cves(cves))))]
    if statement.strip() == "{{EPSS_CACHE}}":
        if not cves:
            raise RuntimeError("{{EPSS_CACHE}} needs the matched CVE list")
        return cache_statements(len(chunk_cves(cves)))
    return [statement]


def ignorable(statement: str, message: str) -> str | None:
    lowered = message.lower()
    head = statement.lstrip().lower()
    if head.startswith("drop") and any(phrase in lowered for phrase in MISSING_OBJECT):
        return "missing"
    # An EPSS batch that already exists still has the previous URL. Do not skip it.
    if "epss_batch" in head and head.startswith("create"):
        return None
    if any(phrase in lowered for phrase in ALREADY_EXISTS):
        return "already exists"
    return None


def run_statements(
    env: dict[str, str],
    statements: list[str],
    parts: dict[str, str],
    secrets: list[str],
    *,
    start: int = 1,
) -> int:
    """Run statements. Returns the next index, or 0 on failure."""
    index = start
    for statement in statements:
        if "{{CONTACT_EMAIL}}" in statement and not parts.get("CONTACT_EMAIL"):
            print("FAIL apply: CONTACT_EMAIL is empty", file=sys.stderr)
            return 0
        filled = fill(statement, parts) if "{{" in statement else statement
        if "{{" in filled:
            print(f"FAIL apply: unfilled placeholder in {first_line(statement)}", file=sys.stderr)
            return 0
        label = first_line(statement)
        result = run_sql(env, filled, timeout=180)
        if result["error"] is None:
            print(f"ok {index} {label}  ms={result['ms']}")
            index += 1
            continue
        message = redact(result["error"], *secrets)
        reason = ignorable(statement, message)
        if reason:
            print(f"skip {index} {label}  {reason}")
            index += 1
            continue
        print(f"FAIL {index} {label}  HTTP {result['status']} {message[:500]}", file=sys.stderr)
        return 0
    return index


def recreate_after_epss(
    env: dict[str, str],
    cves: list[str],
    parts: dict[str, str],
    secrets: list[str],
    start: int,
) -> int:
    """Put v_epss and v_candidate_matches back after the EPSS tables were replaced."""
    batches = chunk_cves(cves)
    statements = [
        "CREATE OR REPLACE SCHEMASTORE VIEW v_epss WITH CONTAINER sibyl_feeds AS\n" + union_body(len(batches))
    ]
    statements.extend(split_sql(CORE_SQL.read_text(encoding="utf-8")))
    statements.extend(cache_statements(len(batches)))
    statements.append("CACHE TABLE sibyl_feeds.v_epss")
    return run_statements(env, statements, parts, secrets, start=start)


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_SQL
    if not path.is_file():
        print(f"FAIL apply: no such file {path}", file=sys.stderr)
        return 1
    env = load_env()
    parts = connection_parts(env)
    if isinstance(parts, str):
        print(f"FAIL apply: {parts}", file=sys.stderr)
        return 1
    text = path.read_text(encoding="utf-8")
    cves: list[str] | None = None
    if "{{EPSS_" in text:
        try:
            cves = load_matched_cves(env.get("DATABASE_URL", ""))
            batches = chunk_cves(cves)
        except (RuntimeError, ValueError, psycopg.Error) as exc:
            detail = exc.__class__.__name__ if isinstance(exc, psycopg.Error) else str(exc)
            print(f"FAIL apply: matched CVE list: {detail}", file=sys.stderr)
            return 1
        print(f"epss matched_cves={len(cves)} batches={len(batches)}")
    secrets = [parts["PG_PASSWORD"], env.get("ZETARIS_API_KEY", ""), parts.get("CONTACT_EMAIL", "")]
    raw_statements = split_sql(text)
    if not raw_statements:
        print(f"FAIL apply: {path} has no statements", file=sys.stderr)
        return 1
    statements: list[str] = []
    replaced_epss = False
    try:
        for statement in raw_statements:
            if "{{EPSS_CVES}}" in statement:
                replaced_epss = True
            statements.extend(expand_statement(statement, cves))
    except (RuntimeError, ValueError) as exc:
        print(f"FAIL apply: {exc}", file=sys.stderr)
        return 1
    applied = run_statements(env, statements, parts, secrets)
    if applied == 0:
        return 1
    if replaced_epss and cves is not None:
        # 02 drops v_epss and v_candidate_matches so the REST tables can be
        # replaced. Put both views back before returning.
        applied = recreate_after_epss(env, cves, parts, secrets, applied)
        if applied == 0:
            return 1
    print(f"applied {applied - 1} statements from {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
