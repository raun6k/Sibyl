"""GitHub Advisory Database collector.

The reviewed advisory payload has `cvss_severities`, not a top-level `cvss`
object. `vulnerable_version_range` is kept as `raw_range`. `first_patched_version`
is stored as `fixed` when the range does not already name one. pip is stored
as the purl type `pypi`.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urlencode

from sibyl.config import Settings
from sibyl.tools.collectors.base import (
    AffectedRow,
    Collector,
    NormalizedRecord,
    RawRecord,
    SeverityRow,
    SourceError,
    dedupe_severity,
    file_time,
    index_rows,
    load_json_path,
    partition_recent,
)
from sibyl.tools.collectors.normalize import alias_pairs, canonical_name, ecosystem_name

GHSA_URL = "https://api.github.com/advisories"
GITHUB_API_VERSION = "2026-03-10"
_BOUND = re.compile(r"^\s*(>=|<=|>|<|=)\s*(.+?)\s*$")


class GhsaCollector(Collector):
    source = "ghsa"
    interval = 0.8

    def read_snapshot(
        self,
        settings: Settings,
        *,
        skip_newer_than: datetime | None = None,
    ) -> tuple[list[RawRecord], list[str]]:
        directory = settings.snapshot_path() / "ghsa"
        if not directory.is_dir():
            raise SourceError("ghsa snapshot directory is missing")
        errors: list[str] = []
        by_id: dict[str, RawRecord] = {}
        list_pages, skipped_pages = partition_recent(
            sorted(directory.glob("advisories-*.json")), skip_newer_than
        )
        advisory_files, skipped_advisories = partition_recent(
            sorted(directory.glob("advisory-*.json")), skip_newer_than
        )
        self.skipped_files = skipped_pages + skipped_advisories
        self.files_read = []
        for path in list_pages + advisory_files:
            self.files_read.append(path.name)
            payload, error = load_json_path(path)
            if error:
                errors.append(error)
                continue
            rows = payload if isinstance(payload, list) else [payload]
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get("ghsa_id"), str):
                    errors.append(f"{path.name}: advisory has no ghsa_id")
                    continue
                by_id[row["ghsa_id"]] = RawRecord(row["ghsa_id"], row, file_time(path), origin=path.name)
        return list(by_id.values()), errors

    def fetch_live(self, settings: Settings, http, window) -> list[RawRecord]:
        since, until = window or ("2026-10-09T00:00:00Z", "2026-10-23T00:00:00Z")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
        by_id: dict[str, RawRecord] = {}
        now = datetime.now(timezone.utc)
        for ecosystem in ("pip", "npm"):
            url = GHSA_URL + "?" + urlencode(
                {
                    "type": "reviewed",
                    "ecosystem": ecosystem,
                    "modified": f"{since}..{until}",
                    "per_page": 100,
                }
            )
            for _page in range(50):
                response = http.request("GET", url, headers=headers)
                try:
                    payload = response.json()
                except ValueError as exc:
                    raise SourceError("GHSA response was not JSON") from exc
                if not isinstance(payload, list) or not payload:
                    break
                for row in payload:
                    if isinstance(row, dict) and isinstance(row.get("ghsa_id"), str):
                        by_id[row["ghsa_id"]] = RawRecord(row["ghsa_id"], row, now)
                if len(payload) < 100:
                    break
                link = _next_link(response.headers.get("link"))
                if not link:
                    break
                url = link
        return list(by_id.values())

    def normalize(self, raw: RawRecord) -> NormalizedRecord:
        advisory = raw.body
        source_id = str(advisory.get("ghsa_id") or raw.source_id)
        identifiers = [source_id]
        cve_id = advisory.get("cve_id")
        if isinstance(cve_id, str) and cve_id.strip():
            identifiers.append(cve_id.strip())
        for item in advisory.get("identifiers") or []:
            if isinstance(item, dict) and isinstance(item.get("value"), str):
                identifiers.append(item["value"])
        affected = _affected(advisory, source_id)
        index_rows(affected)
        status = "withdrawn" if advisory.get("withdrawn_at") else "active"
        return NormalizedRecord(
            source=self.source,
            source_id=source_id,
            status=status,
            body=advisory,
            aliases=alias_pairs(identifiers),
            affected=affected,
            severities=dedupe_severity(_severities(advisory, source_id)),
            retrieved_at=raw.retrieved_at,
        )


def _affected(advisory: dict, vuln_id: str) -> list[AffectedRow]:
    rows: list[AffectedRow] = []
    for vuln in advisory.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        package = vuln.get("package") or {}
        ecosystem = ecosystem_name(package.get("ecosystem"))
        name = package.get("name")
        if not ecosystem or not isinstance(name, str) or not name.strip():
            continue
        patched = _patched(vuln.get("first_patched_version"))
        raw_range = vuln.get("vulnerable_version_range")
        raw_text = raw_range.strip() if isinstance(raw_range, str) else ""
        parts = _parse_range(raw_text, patched)
        if not parts:
            continue
        for part in parts:
            rows.append(
                AffectedRow(
                    vuln_id=vuln_id,
                    ecosystem=ecosystem,
                    package=canonical_name(ecosystem, name),
                    range_type="GHSA",
                    introduced=part["introduced"],
                    fixed=part["fixed"],
                    last_affected=part["last_affected"],
                    raw_range=part["raw_range"],
                )
            )
    return rows


def _parse_range(text: str, patched: str | None) -> list[dict]:
    if not text and not patched:
        return []
    if not text:
        return [{"introduced": None, "fixed": patched, "last_affected": None, "raw_range": None}]
    rows = []
    for part in text.split("||"):
        introduced = fixed = last = None
        for clause in part.split(","):
            match = _BOUND.match(clause)
            if not match:
                continue
            op, version = match.group(1), match.group(2).strip()
            if op == ">=":
                introduced = version
            elif op == ">":
                introduced = version
            elif op == "<":
                fixed = version
            elif op == "<=":
                last = version
            elif op == "=":
                introduced = version
                last = version
        if patched and fixed is None:
            fixed = patched
        rows.append(
            {
                "introduced": introduced,
                "fixed": fixed,
                "last_affected": last,
                "raw_range": part.strip(),
            }
        )
    return rows


def _patched(value) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        text = value.get("identifier") or value.get("version") or ""
        if isinstance(text, str) and text.strip():
            return text.strip()
    return None


def _severities(advisory: dict, vuln_id: str) -> list[SeverityRow]:
    block = advisory.get("cvss_severities") or {}
    if not isinstance(block, dict):
        return []
    rows: list[SeverityRow] = []
    for key, version in (("cvss_v2", "2.0"), ("cvss_v3", "3.1"), ("cvss_v4", "4.0")):
        metric = block.get(key) or {}
        if not isinstance(metric, dict):
            continue
        vector = metric.get("vector_string")
        score = metric.get("score")
        vector_text = vector.strip() if isinstance(vector, str) and vector.strip() else None
        numeric = float(score) if isinstance(score, (int, float)) and vector_text else None
        if vector_text is None:
            continue
        if isinstance(vector_text, str) and vector_text.startswith("CVSS:"):
            version = vector_text.split("/", 1)[0].split(":", 1)[1]
        rows.append(
            SeverityRow(vuln_id=vuln_id, source="ghsa", vector=vector_text, score=numeric, version=version)
        )
    return rows


def _next_link(header: str | None) -> str | None:
    if not header:
        return None
    for part in header.split(","):
        if 'rel="next"' not in part:
            continue
        url = part.split(";", 1)[0].strip().strip("<>")
        if url:
            return url
    return None
