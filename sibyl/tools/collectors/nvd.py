"""NVD 2.0 collector.

CPE matches are stored with range_type NVD_CPE for baseline B1. The CPE
string stays in raw_range. A versionStartExcluding bound is recorded in that
string as start_excluding=<version> so version_eval can treat it as exclusive.
Rejected vulnStatus is stored as status rejected.
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
from sibyl.tools.collectors.normalize import canonical_name

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVSS_LISTS = {
    "cvssMetricV2": "2.0",
    "cvssMetricV30": "3.0",
    "cvssMetricV31": "3.1",
    "cvssMetricV40": "4.0",
}


class NvdCollector(Collector):
    source = "nvd"
    interval = 6.0

    def read_snapshot(
        self,
        settings: Settings,
        *,
        skip_newer_than: datetime | None = None,
    ) -> tuple[list[RawRecord], list[str]]:
        directory = settings.snapshot_path() / "nvd"
        if not directory.is_dir():
            raise SourceError("nvd snapshot directory is missing")
        errors: list[str] = []
        by_id: dict[str, RawRecord] = {}
        windows, skipped_windows = partition_recent(
            sorted(path for path in directory.glob("window-*.json*") if ".json" in path.name),
            skip_newer_than,
        )
        per_cve, skipped_cves = partition_recent(sorted(directory.glob("cve-*.json")), skip_newer_than)
        self.skipped_files = skipped_windows + skipped_cves
        self.files_read = []
        for path in windows + per_cve:
            self.files_read.append(path.name)
            payload, error = load_json_path(path)
            if error or not isinstance(payload, dict):
                errors.append(error or f"{path.name}: not an object")
                continue
            for item in payload.get("vulnerabilities") or []:
                if not isinstance(item, dict):
                    continue
                cve_id = ((item.get("cve") or {}).get("id")) if isinstance(item.get("cve"), dict) else None
                if not isinstance(cve_id, str):
                    errors.append(f"{path.name}: vulnerability has no cve id")
                    continue
                by_id[cve_id] = RawRecord(cve_id, item, file_time(path), origin=path.name)
        return list(by_id.values()), errors

    def fetch_live(self, settings: Settings, http, window) -> list[RawRecord]:
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else None
        by_id: dict[str, RawRecord] = {}
        now = datetime.now(timezone.utc)
        if settings.workspace_id:
            # A workspace ingest asks for its own CVEs by id, not a time window.
            for cve_id in settings.target_cves:
                payload = http.get_json(NVD_URL + "?" + urlencode({"cveId": cve_id}), headers=headers)
                for item in (payload.get("vulnerabilities") or []) if isinstance(payload, dict) else []:
                    found = ((item.get("cve") or {}).get("id")) if isinstance(item, dict) else None
                    if isinstance(found, str):
                        by_id[found] = RawRecord(found, item, now)
            return list(by_id.values())
        since, until = window or ("2026-10-09T00:00:00Z", "2026-10-23T00:00:00Z")
        start = 0
        for _page in range(50):
            url = NVD_URL + "?" + urlencode(
                {
                    "lastModStartDate": _nvd_stamp(since),
                    "lastModEndDate": _nvd_stamp(until),
                    "resultsPerPage": 2000,
                    "startIndex": start,
                }
            )
            payload = http.get_json(url, headers=headers)
            if not isinstance(payload, dict):
                raise SourceError("NVD response was not an object")
            for item in payload.get("vulnerabilities") or []:
                cve_id = ((item.get("cve") or {}).get("id")) if isinstance(item, dict) else None
                if isinstance(cve_id, str):
                    by_id[cve_id] = RawRecord(cve_id, item, now)
            total = int(payload.get("totalResults") or 0)
            per_page = int(payload.get("resultsPerPage") or 0)
            start += per_page
            if per_page <= 0 or start >= total:
                break
        return list(by_id.values())

    def normalize(self, raw: RawRecord) -> NormalizedRecord:
        cve = raw.body.get("cve") if isinstance(raw.body.get("cve"), dict) else {}
        source_id = str(cve.get("id") or raw.source_id)
        affected = _cpe_rows(cve, source_id)
        index_rows(affected)
        status = "rejected" if "reject" in str(cve.get("vulnStatus") or "").lower() else "active"
        return NormalizedRecord(
            source=self.source,
            source_id=source_id,
            status=status,
            body=raw.body,
            aliases=[],
            affected=affected,
            severities=dedupe_severity(_severities(cve, source_id)),
            retrieved_at=raw.retrieved_at,
        )


def _cpe_rows(cve: dict, vuln_id: str) -> list[AffectedRow]:
    rows: list[AffectedRow] = []
    for config in cve.get("configurations") or []:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict) or match.get("vulnerable") is False:
                    continue
                row = _one_cpe(match, vuln_id)
                if row is not None:
                    rows.append(row)
    return rows


def _one_cpe(match: dict, vuln_id: str) -> AffectedRow | None:
    criteria = str(match.get("criteria") or "")
    parts = re.split(r"(?<!\\):", criteria)
    if len(parts) < 6:
        return None
    product = parts[4].replace("\\:", ":")
    version = parts[5].replace("\\:", ":")
    target = parts[10].replace("\\:", ":") if len(parts) > 10 else "*"
    if product in {"*", "-"}:
        return None
    target_name = target.lower()
    if target_name in {"python", "pypi"}:
        ecosystem = "pypi"
        package = canonical_name("pypi", product)
    elif target_name in {"node.js", "nodejs", "npm"}:
        ecosystem = "npm"
        package = product.lower()
    else:
        ecosystem = "nvd"
        package = product.lower()
    introduced = _bound(match.get("versionStartIncluding"))
    fixed = _bound(match.get("versionEndExcluding"))
    last_affected = _bound(match.get("versionEndIncluding"))
    raw = criteria
    start_excluding = _bound(match.get("versionStartExcluding"))
    if start_excluding and not introduced:
        introduced = start_excluding
        raw = f"{criteria} start_excluding={start_excluding}"
    has_bounds = any([introduced, fixed, last_affected, start_excluding])
    if not has_bounds and version not in {"*", "-"}:
        introduced = version
        last_affected = version
    elif not has_bounds and version == "*":
        introduced = "0"
    elif not has_bounds:
        return None
    return AffectedRow(
        vuln_id=vuln_id,
        ecosystem=ecosystem,
        package=package,
        range_type="NVD_CPE",
        introduced=introduced,
        fixed=fixed,
        last_affected=last_affected,
        raw_range=raw,
    )


def _severities(cve: dict, vuln_id: str) -> list[SeverityRow]:
    rows: list[SeverityRow] = []
    metrics = cve.get("metrics") or {}
    if not isinstance(metrics, dict):
        return rows
    for key, fallback in _CVSS_LISTS.items():
        for item in metrics.get(key) or []:
            if not isinstance(item, dict):
                continue
            data = item.get("cvssData") or {}
            if not isinstance(data, dict):
                continue
            vector = data.get("vectorString")
            vector_text = vector.strip() if isinstance(vector, str) and vector.strip() else None
            score = data.get("baseScore")
            numeric = float(score) if isinstance(score, (int, float)) else None
            version = str(data.get("version") or fallback)
            if vector_text is None and numeric is None:
                continue
            source = "nvd"
            metric_type = item.get("type")
            if isinstance(metric_type, str) and metric_type.strip():
                source = f"nvd:{metric_type.strip().lower()}"
            rows.append(
                SeverityRow(
                    vuln_id=vuln_id,
                    source=source,
                    vector=vector_text,
                    score=numeric,
                    version=version,
                )
            )
    return rows


def _bound(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _nvd_stamp(value: str) -> str:
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
