"""CISA KEV collector. One source record per catalogue entry.

Zetaris reads the same feed as a REST table. These rows are the fallback.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sibyl.config import Settings
from sibyl.tools.collectors.base import (
    Collector,
    NormalizedRecord,
    RawRecord,
    SourceError,
    file_time,
    load_json_path,
    snapshot_file,
)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevCollector(Collector):
    source = "kev"
    interval = 0.0

    def read_snapshot(self, settings: Settings) -> tuple[list[RawRecord], list[str]]:
        path = snapshot_file(settings.snapshot_path() / "kev", "known_exploited_vulnerabilities.json")
        if path is None:
            raise SourceError("KEV snapshot is missing")
        payload, error = load_json_path(path)
        if error or not isinstance(payload, dict):
            return [], [error or "KEV snapshot was not an object"]
        records: list[RawRecord] = []
        errors: list[str] = []
        moment = file_time(path)
        for item in payload.get("vulnerabilities") or []:
            if not isinstance(item, dict) or not isinstance(item.get("cveID"), str):
                errors.append("KEV entry has no cveID")
                continue
            records.append(RawRecord(item["cveID"], item, moment))
        return records, errors

    def fetch_live(self, settings: Settings, http, window) -> list[RawRecord]:
        payload = http.get_json(KEV_URL)
        if not isinstance(payload, dict):
            raise SourceError("KEV response was not an object")
        now = datetime.now(timezone.utc)
        records: list[RawRecord] = []
        for item in payload.get("vulnerabilities") or []:
            if isinstance(item, dict) and isinstance(item.get("cveID"), str):
                records.append(RawRecord(item["cveID"], item, now))
        return records

    def normalize(self, raw: RawRecord) -> NormalizedRecord:
        return NormalizedRecord(
            source=self.source,
            source_id=raw.source_id,
            status="active",
            body=raw.body,
            retrieved_at=raw.retrieved_at,
        )
