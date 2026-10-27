"""First-time setup after `uv sync`, `docker compose up -d` and a filled `.env`.

Runs, in order:
1. Build the World Model and H-MEM engines (needs `npm --prefix engines install`).
2. Apply the Postgres schemas and seed the sample workspace (`seed_db.py`).
3. Ingest the sample evidence from SNAPSHOT_DIR.
4. Register Postgres and the public feeds in Zetaris: 04, 01, 02, 03, 05.

Every step is safe to repeat. Zetaris statements that already exist are
skipped; 02 replaces the EPSS tables with the current matched CVE set.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from apply_zetaris_sql import main as apply_sql  # noqa: E402
from seed_db import main as seed_main  # noqa: E402

SQL = ROOT / "zetaris" / "sql"
# 04 registers Postgres first because 03 and 05 read its tables. 02 needs the
# ingested CVEs for its EPSS URLs; 03 and 05 then create the views.
ZETARIS_ORDER = ("04_postgres.sql", "01_databases.sql", "02_rest_tables.sql", "03_views.sql", "05_core_views.sql")


def build_engines() -> None:
    from sibyl.engines.hmem import compile_hmem
    from sibyl.engines.world_model import compile_world_model

    if shutil.which("node") is None:
        raise SystemExit("FAIL setup: node is not on PATH (Node 20 or later)")
    try:
        compile_world_model()
        compile_hmem()
    except RuntimeError as exc:
        raise SystemExit(f"FAIL setup: {exc}") from exc
    print("ok engines built")


def ingest_sample() -> None:
    from sibyl.config import load_settings
    from sibyl.tools.collectors import ingest

    for item in ingest(settings=load_settings()):
        print(item.summary())
        for error in item.errors:
            print(f"  {error}")


def main() -> int:
    build_engines()
    if seed_main([]) != 0:
        return 1
    ingest_sample()
    for name in ZETARIS_ORDER:
        print(f"zetaris {name}")
        if apply_sql(["apply_zetaris_sql.py", str(SQL / name)], recreate=False) != 0:
            return 1
    print("setup done. Next: uv run tests/smoke_test.py, then scripts/dev.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main())
