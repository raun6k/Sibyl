"""CVE.org collector.

CNA `affected[]` becomes a range only when the object identifies a PyPI or
npm package (a purl, or a collectionURL on pypi.org / npmjs) and the version
is machine-readable. Vendor/product prose such as "versions prior to 4.17.21"
does not. A version object whose status is unaffected or unknown is not a
range. A lone version is that one version, not an open `>=`. A git commit
bound is skipped. CNA metrics and the CISA-ADP container are stored as
separate severity rows.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from packageurl import PackageURL

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

CVE_URL = "https://cveawg.mitre.org/api/cve/{id}"
_CVSS_KEYS = {
    "cvssV2_0": "2.0",
    "cvssV3_0": "3.0",
    "cvssV3_1": "3.1",
    "cvssV4_0": "4.0",
}
_PROSE = re.compile(r"prior to|versions |and earlier|and later|see |n/a|unspecified", re.IGNORECASE)
_COMMIT = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)
_OPEN = {"0", "0.0.0", "0.0.0.0", "*"}


class CveOrgCollector(Collector):
    source = "cve_org"
    interval = 0.3

    def read_snapshot(
        self,
        settings: Settings,
        *,
        skip_newer_than: datetime | None = None,
    ) -> tuple[list[RawRecord], list[str]]:
        directory = settings.snapshot_path() / "cve"
        if not directory.is_dir():
            raise SourceError("cve snapshot directory is missing")
        records: list[RawRecord] = []
        errors: list[str] = []
        paths, skipped = partition_recent(sorted(directory.glob("CVE-*.json")), skip_newer_than)
        self.files_read = []
        self.skipped_files = skipped
        for path in paths:
            self.files_read.append(path.name)
            payload, error = load_json_path(path)
            if error or not isinstance(payload, dict):
                errors.append(error or f"{path.name}: not an object")
                continue
            cve_id = ((payload.get("cveMetadata") or {}).get("cveId")) or path.stem
            records.append(RawRecord(str(cve_id), payload, file_time(path), origin=path.name))
        return records, errors

    def fetch_live(self, settings: Settings, http, window) -> list[RawRecord]:
        raise SourceError("CVE.org live fetch needs ids; use the snapshot")

    def normalize(self, raw: RawRecord) -> NormalizedRecord:
        document = raw.body
        source_id = str((document.get("cveMetadata") or {}).get("cveId") or raw.source_id)
        state = str((document.get("cveMetadata") or {}).get("state") or "")
        status = "rejected" if state.upper() == "REJECTED" else "active"
        affected = _affected(document, source_id)
        index_rows(affected)
        return NormalizedRecord(
            source=self.source,
            source_id=source_id,
            status=status,
            body=document,
            aliases=[],
            affected=affected,
            severities=dedupe_severity(_severities(document, source_id)),
            retrieved_at=raw.retrieved_at,
        )


def _affected(document: dict, vuln_id: str) -> list[AffectedRow]:
    cna = (document.get("containers") or {}).get("cna") or {}
    rows: list[AffectedRow] = []
    for item in cna.get("affected") or []:
        if not isinstance(item, dict):
            continue
        identified = _package(item)
        if identified is None:
            continue
        ecosystem, package = identified
        for version in item.get("versions") or []:
            if not isinstance(version, dict):
                continue
            parsed = _version_bounds(version)
            if parsed is None:
                continue
            introduced, fixed, last_affected, raw_range = parsed
            rows.append(
                AffectedRow(
                    vuln_id=vuln_id,
                    ecosystem=ecosystem,
                    package=package,
                    range_type="CNA",
                    introduced=introduced,
                    fixed=fixed,
                    last_affected=last_affected,
                    raw_range=raw_range,
                )
            )
    return rows


def _package(item: dict) -> tuple[str, str] | None:
    for key in ("purl", "packageURL"):
        purl = item.get(key)
        if isinstance(purl, str) and purl.startswith("pkg:"):
            parsed = PackageURL.from_string(purl.split("?", 1)[0])
            ecosystem = (parsed.type or "").lower()
            if ecosystem in {"pypi", "npm"} and parsed.name:
                return ecosystem, canonical_name(ecosystem, parsed.name)
    collection = str(item.get("collectionURL") or "").lower()
    name = item.get("packageName") or item.get("product")
    if not isinstance(name, str) or not name.strip():
        return None
    if "pypi.org" in collection:
        return "pypi", canonical_name("pypi", name)
    if "npmjs.com" in collection or "npmjs.org" in collection:
        return "npm", name.strip().lower()
    return None


def _is_comparator(text: str) -> bool:
    return text.startswith((">=", "<=", ">", "<", "="))


def _bound(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _is_commit(text: str | None) -> bool:
    return bool(text and _COMMIT.fullmatch(text))


def _version_bounds(version: dict) -> tuple[str | None, str | None, str | None, str] | None:
    """Return introduced, fixed, last_affected, raw_range. None skips the object.

    `status: unaffected` is not an affected range. A git commit id is not a
    version. With no lessThan and no lessThanOrEqual, the version is exact:
    `1.0` must not become `>= 1.0`. `introduced` of `0` stays open.
    """
    status = str(version.get("status") or "affected").strip().lower()
    if status in {"unaffected", "unknown"}:
        return None
    text = str(version.get("version") or "").strip()
    fixed = _bound(version.get("lessThan"))
    last_affected = _bound(version.get("lessThanOrEqual"))
    if any(_is_commit(value) for value in (text, fixed, last_affected)):
        return None
    comparator = _is_comparator(text)
    prose = (not text) or bool(_PROSE.search(text)) or not re.search(r"\d", text)
    if comparator:
        return None, fixed, last_affected, text
    if prose:
        if not fixed and not last_affected:
            return None
        if fixed and (not re.search(r"\d", fixed) or _PROSE.search(fixed)):
            return None
        if last_affected and (not re.search(r"\d", last_affected) or _PROSE.search(last_affected)):
            return None
        return "0", fixed, last_affected, text or fixed or last_affected or ""
    if not fixed and not last_affected and text not in _OPEN:
        last_affected = text
    return text, fixed, last_affected, text


def _severities(document: dict, vuln_id: str) -> list[SeverityRow]:
    containers = document.get("containers") or {}
    rows: list[SeverityRow] = []
    cna = containers.get("cna") or {}
    rows.extend(_metric_rows(cna.get("metrics"), vuln_id, "cna"))
    for adp in containers.get("adp") or []:
        if not isinstance(adp, dict):
            continue
        short = str((adp.get("providerMetadata") or {}).get("shortName") or "adp")
        source = "cisa-adp" if "cisa" in short.lower() else f"adp:{short.lower()}"
        rows.extend(_metric_rows(adp.get("metrics"), vuln_id, source))
    return rows


def _metric_rows(metrics, vuln_id: str, source: str) -> list[SeverityRow]:
    if isinstance(metrics, dict):
        metrics = [metrics]
    if not isinstance(metrics, list):
        return []
    rows: list[SeverityRow] = []
    for item in metrics:
        if not isinstance(item, dict):
            continue
        for key, fallback in _CVSS_KEYS.items():
            data = item.get(key)
            if not isinstance(data, dict):
                continue
            vector = data.get("vectorString")
            vector_text = vector.strip() if isinstance(vector, str) and vector.strip() else None
            score = data.get("baseScore")
            numeric = float(score) if isinstance(score, (int, float)) else None
            if vector_text is None and numeric is None:
                continue
            version = str(data.get("version") or fallback)
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
