"""FIRST EPSS collector. One source record per scored CVE.

Zetaris reads a fixed EPSS URL as a REST table. These rows are the fallback.
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
)

EPSS_URL = "https://api.first.org/data/v1/epss"


class EpssCollector(Collector):
    source = "epss"
    interval = 0.4

    def read_snapshot(self, settings: Settings) -> tuple[list[RawRecord], list[str]]:
        directory = settings.snapshot_path() / "epss"
        if not directory.is_dir():
            raise SourceError("epss snapshot directory is missing")
        by_id: dict[str, RawRecord] = {}
        errors: list[str] = []
        for path in sorted(directory.glob("batch-*.json")):
            payload, error = load_json_path(path)
            if error or not isinstance(payload, dict):
                errors.append(error or f"{path.name}: not an object")
                continue
            moment = file_time(path)
            for item in payload.get("data") or []:
                if not isinstance(item, dict) or not isinstance(item.get("cve"), str):
                    errors.append(f"{path.name}: EPSS row has no cve")
                    continue
                by_id[item["cve"]] = RawRecord(item["cve"], item, moment)
        return list(by_id.values()), errors

    def fetch_live(self, settings: Settings, http, window) -> list[RawRecord]:
        payload = http.get_json(EPSS_URL)
        if not isinstance(payload, dict):
            raise SourceError("EPSS response was not an object")
        now = datetime.now(timezone.utc)
        records = []
        for item in payload.get("data") or []:
            if isinstance(item, dict) and isinstance(item.get("cve"), str):
                records.append(RawRecord(item["cve"], item, now))
        return records

    def normalize(self, raw: RawRecord) -> NormalizedRecord:
        return NormalizedRecord(
            source=self.source,
            source_id=raw.source_id,
            status="active",
            body=raw.body,
            retrieved_at=raw.retrieved_at,
        )
