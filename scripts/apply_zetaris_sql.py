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

from zetaris_rest import load_env, redact, run_sql, split_sql

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SQL = ROOT / "zetaris" / "sql" / "04_postgres.sql"

ALREADY_EXISTS = (
    "already exists",
    "already registered",
    "name exist",
    "datasource name exist",
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
    secrets = [parts["PG_PASSWORD"], env.get("ZETARIS_API_KEY", ""), parts.get("CONTACT_EMAIL", "")]
    statements = split_sql(path.read_text(encoding="utf-8"))
    if not statements:
        print(f"FAIL apply: {path} has no statements", file=sys.stderr)
        return 1
    for index, statement in enumerate(statements, start=1):
        if "{{CONTACT_EMAIL}}" in statement and not parts.get("CONTACT_EMAIL"):
            print("FAIL apply: CONTACT_EMAIL is empty", file=sys.stderr)
            return 1
        if "{{" in statement:
            filled = fill(statement, parts)
        else:
            filled = statement
        label = first_line(statement)
        result = run_sql(env, filled, timeout=120)
        if result["error"] is None:
            print(f"ok {index} {label}  ms={result['ms']}")
            continue
        message = redact(result["error"], *secrets)
        lowered = message.lower()
        if any(phrase in lowered for phrase in ALREADY_EXISTS):
            print(f"skip {index} {label}  already exists")
            continue
        print(f"FAIL {index} {label}  HTTP {result['status']} {message[:500]}", file=sys.stderr)
        return 1
    print(f"applied {len(statements)} statements from {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
