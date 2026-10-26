"""Rebuild the Zetaris EPSS REST tables when the matched CVE set changes.

EPSS reaches a case through `v_epss`, whose REST tables carry the matched
CVE ids in their URLs (at most 100 per table). A live workspace ingest can
add CVEs, so the tables are rebuilt with `scripts/apply_zetaris_sql.py` on
`02_rest_tables.sql`, which also puts `v_epss` and `v_candidate_matches`
back. The last applied set's hash is kept in `var/`, so an unchanged set
costs one Postgres query.
"""

from __future__ import annotations

import hashlib
import sys
import threading

from sibyl.config import ROOT, Settings

STATE = ROOT / "var" / "epss-cves.sha256"
SQL = ROOT / "zetaris" / "sql" / "02_rest_tables.sql"
_lock = threading.Lock()


def refresh_epss(settings: Settings) -> dict[str, object]:
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    from apply_zetaris_sql import main as apply_main
    from epss_batches import load_matched_cves

    with _lock:
        cves = load_matched_cves(settings.database_url)
        digest = hashlib.sha256(",".join(cves).encode()).hexdigest()
        if STATE.is_file() and STATE.read_text(encoding="utf-8").strip() == digest:
            return {"changed": False, "cves": len(cves)}
        code = apply_main(["apply_zetaris_sql.py", str(SQL)])
        if code != 0:
            raise RuntimeError("rebuilding the EPSS tables in Zetaris failed")
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(digest, encoding="utf-8")
        return {"changed": True, "cves": len(cves)}
