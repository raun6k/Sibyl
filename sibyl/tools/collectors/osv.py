"""OSV collector. Snapshot files follow scripts/snapshot_sources.py.

Vulnerability documents are `vuln-<id>.json`. Query-batch files are paired
with `querybatch-NNN.request.json` when that file exists, otherwise the
request is rebuilt from the Acme SBOM purls the same way `fetch_osv` builds it.
GIT ranges are counted and not stored. Ecosystem names are stored as purl types.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import psycopg

from sibyl.config import ROOT, Settings
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
    modified_after,
    partition_recent,
)
from sibyl.tools.collectors.normalize import (
    alias_pairs,
    canonical_name,
    cvss3_score,
    ecosystem_name,
    vector_version,
)
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
SBOM_DIR = ROOT / "data" / "sample" / "sboms"
SERVICES = ("checkout-api", "merchant-portal", "reporting-worker", "internal-admin")


class OsvCollector(Collector):
    source = "osv"
    interval = 0.2

    def read_snapshot(
        self,
        settings: Settings,
        *,
        skip_newer_than: datetime | None = None,
    ) -> tuple[list[RawRecord], list[str]]:
        directory = settings.snapshot_path() / "osv"
        if not directory.is_dir():
            raise SourceError("osv snapshot directory is missing")
        vuln_paths, vuln_skipped = partition_recent(sorted(directory.glob("vuln-*.json")), skip_newer_than)
        batch_paths, batch_skipped = _batch_paths(directory, skip_newer_than)
        self.files_read = [path.name for path in batch_paths]
        self.skipped_files = vuln_skipped + batch_skipped
        errors = _check_batches(batch_paths, _sbom_purls())
        records: list[RawRecord] = []
        for path in vuln_paths:
            self.files_read.append(path.name)
            payload, error = load_json_path(path)
            if error or not isinstance(payload, dict) or not payload.get("id"):
                errors.append(error or f"{path.name}: missing id")
                continue
            records.append(RawRecord(str(payload["id"]), payload, file_time(path), origin=path.name))
        return records, errors

    def fetch_live(self, settings: Settings, http, window) -> list[RawRecord]:
        purls = _db_purls(settings)
        if not purls:
            raise SourceError("no component purls to query")
        identifiers: list[str] = []
        seen: set[str] = set()
        for index in range(0, len(purls), 100):
            batch = purls[index : index + 100]
            body = {"queries": [{"package": {"purl": purl}} for purl in batch]}
            payload = http.post_json(OSV_BATCH_URL, body)
            results = payload.get("results") if isinstance(payload, dict) else None
            if not isinstance(results, list) or len(results) != len(batch):
                raise SourceError(f"querybatch {index // 100} length mismatch")
            for item in results:
                for vuln in (item or {}).get("vulns") or []:
                    identifier = vuln.get("id") if isinstance(vuln, dict) else None
                    if identifier and identifier not in seen:
                        seen.add(identifier)
                        identifiers.append(identifier)
        records: list[RawRecord] = []
        now = datetime.now(timezone.utc)
        for identifier in identifiers:
            payload = http.get_json(OSV_VULN_URL.format(id=identifier))
            if isinstance(payload, dict) and payload.get("id"):
                records.append(RawRecord(str(payload["id"]), payload, now))
        return records

    def normalize(self, raw: RawRecord) -> NormalizedRecord:
        document = raw.body
        source_id = str(document.get("id") or raw.source_id)
        aliases = [source_id]
        for alias in document.get("aliases") or []:
            if isinstance(alias, str):
                aliases.append(alias)
        affected, skipped = _affected(document, source_id)
        index_rows(affected)
        severities = dedupe_severity(_severities(document, source_id))
        status = "withdrawn" if document.get("withdrawn") else "active"
        return NormalizedRecord(
            source=self.source,
            source_id=source_id,
            status=status,
            body=document,
            aliases=alias_pairs(aliases),
            affected=affected,
            severities=severities,
            git_ranges_skipped=skipped,
            retrieved_at=raw.retrieved_at,
        )


def _affected(document: dict, vuln_id: str) -> tuple[list[AffectedRow], int]:
    rows: list[AffectedRow] = []
    skipped = 0
    for affected in document.get("affected") or []:
        package = affected.get("package") or {}
        ecosystem = ecosystem_name(package.get("ecosystem"))
        name = package.get("name") or ""
        if not ecosystem or not isinstance(name, str) or not name.strip():
            for rng in affected.get("ranges") or []:
                if isinstance(rng, dict) and rng.get("type") == "GIT":
                    skipped += 1
            continue
        package_name = canonical_name(ecosystem, name)
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            range_type = str(rng.get("type") or "ECOSYSTEM")
            if range_type == "GIT":
                skipped += 1
                continue
            for interval in _intervals(rng.get("events") or []):
                rows.append(
                    AffectedRow(
                        vuln_id=vuln_id,
                        ecosystem=ecosystem,
                        package=package_name,
                        range_type=range_type,
                        introduced=interval.get("introduced"),
                        fixed=interval.get("fixed"),
                        last_affected=interval.get("last_affected"),
                        raw_range=json.dumps(interval["events"], separators=(",", ":")),
                    )
                )
        for version in affected.get("versions") or []:
            if isinstance(version, str) and version.strip():
                rows.append(
                    AffectedRow(
                        vuln_id=vuln_id,
                        ecosystem=ecosystem,
                        package=package_name,
                        range_type="VERSIONS",
                        introduced=version,
                        last_affected=version,
                        raw_range=version,
                    )
                )
    return rows, skipped


def _intervals(events: list) -> list[dict]:
    found: list[dict] = []
    current: dict | None = None
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            if current:
                found.append(current)
            current = {
                "introduced": _text(event.get("introduced")),
                "fixed": None,
                "last_affected": None,
                "events": [event],
            }
        elif current is not None and "fixed" in event:
            current["fixed"] = _text(event.get("fixed"))
            current["events"].append(event)
            found.append(current)
            current = None
        elif current is not None and "last_affected" in event:
            current["last_affected"] = _text(event.get("last_affected"))
            current["events"].append(event)
            found.append(current)
            current = None
    if current:
        found.append(current)
    return found


def _severities(document: dict, vuln_id: str) -> list[SeverityRow]:
    rows: list[SeverityRow] = []
    for item in document.get("severity") or []:
        if not isinstance(item, dict):
            continue
        score = item.get("score")
        vector = score if isinstance(score, str) else None
        version = vector_version(vector)
        numeric = cvss3_score(vector) if vector else None
        if numeric is None and isinstance(score, (int, float)):
            numeric = float(score)
        if not vector and numeric is None:
            continue
        rows.append(
            SeverityRow(
                vuln_id=vuln_id,
                source="osv",
                vector=vector,
                score=numeric,
                version=version or str(item.get("type") or ""),
            )
        )
    return rows


def _text(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def query_index(directory: Path) -> dict[str, set[str]]:
    """Purl to the vuln ids OSV returned for it.

    A purl with an empty set was queried and listed nothing. Purls that were
    not in a query batch are absent. Ids are the OSV ids in the response,
    usually GHSA or PYSEC, not the CVE alias.
    """
    found: dict[str, set[str]] = {}
    purls: list[str] | None = None
    if not directory.is_dir():
        return found
    for path in sorted(directory.glob("querybatch-*.json")):
        if path.name.endswith(".request.json"):
            continue
        payload, error = load_json_path(path)
        if error or not isinstance(payload, dict):
            continue
        index = int(path.name.split("-")[1].split(".")[0])
        request_path = directory / f"querybatch-{index:03d}.request.json"
        if request_path.is_file():
            request, request_error = load_json_path(request_path)
            queries = request.get("queries") if isinstance(request, dict) else None
            if request_error or not isinstance(queries, list):
                continue
        else:
            # The full snapshot stores the response only. fetch_osv queried
            # the sorted Acme purls, 100 per file, in that same order.
            if purls is None:
                purls = _sbom_purls()
            queries = [{"package": {"purl": purl}} for purl in purls[index * 100 : (index + 1) * 100]]
        results = payload.get("results") or []
        if len(results) != len(queries):
            continue
        for query, result in zip(queries, results):
            package = query.get("package") if isinstance(query, dict) else None
            purl = package.get("purl") if isinstance(package, dict) else None
            if not isinstance(purl, str) or not purl:
                continue
            ids = found.setdefault(purl, set())
            vulns = result.get("vulns") if isinstance(result, dict) else None
            for vuln in vulns or []:
                identifier = vuln.get("id") if isinstance(vuln, dict) else None
                if isinstance(identifier, str) and identifier:
                    ids.add(identifier)
    return found


def _batch_paths(directory: Path, skip_newer_than: datetime | None) -> tuple[list[Path], list[str]]:
    """Query-batch responses, skipping a file still being written.

    The paired request is skipped with the response. A half-written request
    would otherwise look like a length mismatch.
    """
    kept: list[Path] = []
    skipped: list[str] = []
    for path in sorted(directory.glob("querybatch-*.json")):
        if path.name.endswith(".request.json"):
            continue
        request = directory / f"{path.stem}.request.json"
        if modified_after(path, skip_newer_than) or (
            request.is_file() and modified_after(request, skip_newer_than)
        ):
            skipped.append(path.name)
            continue
        kept.append(path)
    return kept, skipped


def _check_batches(paths: list[Path], purls: list[str]) -> list[str]:
    errors: list[str] = []
    for path in paths:
        payload, error = load_json_path(path)
        if error or not isinstance(payload, dict):
            errors.append(error or f"{path.name}: not an object")
            continue
        index = int(path.name.split("-")[1].split(".")[0])
        request_path = path.parent / f"querybatch-{index:03d}.request.json"
        if request_path.is_file():
            request, request_error = load_json_path(request_path)
            queries = request.get("queries") if isinstance(request, dict) else None
            if request_error or not isinstance(queries, list):
                errors.append(request_error or f"{request_path.name}: not a request")
                continue
        else:
            queries = [{"package": {"purl": purl}} for purl in purls[index * 100 : (index + 1) * 100]]
        results = payload.get("results") or []
        if len(results) != len(queries):
            errors.append(f"{path.name}: {len(results)} results for {len(queries)} queries")
    return errors


def _sbom_purls() -> list[str]:
    found: set[str] = set()
    for service in SERVICES:
        path = SBOM_DIR / f"{service}.cdx.json"
        if not path.is_file():
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        for component in _flatten(document.get("components")):
            purl = component.get("purl") or ""
            if isinstance(purl, str) and purl.startswith("pkg:"):
                found.add(purl)
    return sorted(found)


def _flatten(components: list | None) -> list[dict]:
    found: list[dict] = []
    for component in components or []:
        found.append(component)
        found.extend(_flatten(component.get("components")))
    return found


def _db_purls(settings: Settings) -> list[str]:
    if not settings.database_url:
        raise SourceError("DATABASE_URL is empty")
    with psycopg.connect(settings.database_url) as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT purl FROM acme_internal.components
            WHERE purl LIKE 'pkg:%'
            ORDER BY purl
            """
        ).fetchall()
    return [row[0] for row in rows]
