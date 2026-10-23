"""ENISA EUVD collector.

The exploited list (`GET /api/exploitedvulnerabilities`) does not page. It is
the latest exploited vulnerabilities, at most 8 records. Per-CVE lookups use
`/api/enisaid?id=<CVE>`, which is what `fetch_euvd` calls. `aliases` on both
responses is one newline-separated string. The list's `epss` is a 0–1
probability; the per-id `epss` is a 0–100 percentage. Both are kept in
raw_json and are not coerced into one scale.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from sibyl.config import Settings
from sibyl.tools.collectors.base import (
    Collector,
    NormalizedRecord,
    RawRecord,
    SeverityRow,
    SourceError,
    dedupe_severity,
    file_time,
    load_json_path,
    snapshot_file,
)
from sibyl.tools.collectors.normalize import alias_pairs, vector_version

EUVD_EXPLOITED_URL = "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities"
EUVD_ID_URL = "https://euvdservices.enisa.europa.eu/api/enisaid"
_ID_FILE = re.compile(r"^CVE-")


class EuvdCollector(Collector):
    source = "euvd"
    interval = 0.5

    def read_snapshot(self, settings: Settings) -> tuple[list[RawRecord], list[str]]:
        directory = settings.snapshot_path() / "euvd"
        if not directory.is_dir():
            raise SourceError("euvd snapshot directory is missing")
        errors: list[str] = []
        by_id: dict[str, RawRecord] = {}
        listing = snapshot_file(directory, "exploitedvulnerabilities.json")
        if listing is not None:
            _take(listing, by_id, errors, overwrite=False)
        for path in sorted(directory.glob("*.json")):
            if path.name == "exploitedvulnerabilities.json":
                continue
            if not _ID_FILE.match(path.name):
                continue
            _take(path, by_id, errors, overwrite=True)
        return list(by_id.values()), errors

    def fetch_live(self, settings: Settings, http, window) -> list[RawRecord]:
        payload = http.get_json(EUVD_EXPLOITED_URL)
        now = datetime.now(timezone.utc)
        records: dict[str, RawRecord] = {}
        rows = payload if isinstance(payload, list) else []
        for item in rows:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                records[item["id"]] = RawRecord(item["id"], item, now)
        return list(records.values())

    def normalize(self, raw: RawRecord) -> NormalizedRecord:
        identifiers = [raw.source_id]
        identifiers.extend(_aliases(raw.body.get("aliases")))
        severities: list[SeverityRow] = []
        vector = raw.body.get("baseScoreVector")
        score = raw.body.get("baseScore")
        vector_text = vector.strip() if isinstance(vector, str) and vector.strip() else None
        numeric = float(score) if isinstance(score, (int, float)) else None
        if vector_text or numeric is not None:
            severities.append(
                SeverityRow(
                    vuln_id=raw.source_id,
                    source="euvd",
                    vector=vector_text,
                    score=numeric,
                    version=str(raw.body.get("baseScoreVersion") or vector_version(vector_text)),
                )
            )
        return NormalizedRecord(
            source=self.source,
            source_id=raw.source_id,
            status="active",
            body=raw.body,
            aliases=alias_pairs(identifiers),
            severities=dedupe_severity(severities),
            retrieved_at=raw.retrieved_at,
        )


def _take(path, by_id: dict[str, RawRecord], errors: list[str], overwrite: bool) -> None:
    payload, error = load_json_path(path)
    if error:
        errors.append(error)
        return
    rows = payload if isinstance(payload, list) else [payload]
    moment = file_time(path)
    for item in rows:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            errors.append(f"{path.name}: EUVD object has no id")
            continue
        if overwrite or item["id"] not in by_id:
            by_id[item["id"]] = RawRecord(item["id"], item, moment)


def _aliases(value) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if not isinstance(value, str):
        return []
    return [part.strip() for part in value.replace(",", "\n").split() if part.strip()]
