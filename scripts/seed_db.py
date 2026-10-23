"""Apply the Sibyl Postgres schema and the P1 probe rows.

Reads DATABASE_URL from the repo `.env`. Does not print the URL.
"""

from __future__ import annotations

import sys
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


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


def main() -> int:
    env = load_env(ENV_PATH)
    url = env.get("DATABASE_URL", "")
    if not url:
        print("FAIL seed: missing DATABASE_URL", file=sys.stderr)
        return 1
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    try:
        with psycopg.connect(url) as conn:
            conn.execute(sql)
            services = conn.execute("SELECT count(*) FROM acme_internal.services").fetchone()[0]
            sboms = conn.execute("SELECT count(*) FROM acme_internal.sboms").fetchone()[0]
            components = conn.execute("SELECT count(*) FROM acme_internal.components").fetchone()[0]
            records = conn.execute("SELECT count(*) FROM evidence.source_records").fetchone()[0]
            affected = conn.execute("SELECT count(*) FROM evidence.affected").fetchone()[0]
    except psycopg.Error as exc:
        print(f"FAIL seed: {exc.__class__.__name__}", file=sys.stderr)
        return 1
    print(
        "seeded"
        f" acme_internal.services={services}"
        f" sboms={sboms}"
        f" components={components}"
        f" evidence.source_records={records}"
        f" affected={affected}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
