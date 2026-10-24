"""Collector interface: live HTTP with retries, or files from SNAPSHOT_DIR.

SAMPLE_MODE reads snapshots. In live mode, two failed retries on 429, 5xx, or
a timeout fall back to the snapshot and the source is marked degraded. A
source listed in DISABLE_SOURCES returns nothing and is marked disabled.
"""

from __future__ import annotations

import gzip
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import httpx

from sibyl.config import Settings

RETRY_STATUS = {429, 500, 502, 503, 504}


class SourceError(Exception):
    """A live fetch or a snapshot read could not produce records."""


@dataclass
class RawRecord:
    source_id: str
    body: dict
    retrieved_at: datetime
    origin: str = ""


@dataclass
class AffectedRow:
    vuln_id: str
    ecosystem: str
    package: str
    range_type: str
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    raw_range: str | None = None
    range_index: int = 0


@dataclass
class SeverityRow:
    vuln_id: str
    source: str
    vector: str | None
    score: float | None
    version: str


@dataclass
class NormalizedRecord:
    source: str
    source_id: str
    status: str
    body: dict
    aliases: list[tuple[str, str]] = field(default_factory=list)
    affected: list[AffectedRow] = field(default_factory=list)
    severities: list[SeverityRow] = field(default_factory=list)
    git_ranges_skipped: int = 0
    retrieved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def record_id(self) -> str:
        return f"{self.source}:{self.source_id}"


@dataclass
class SourceBatch:
    source: str
    status: str
    records: list[NormalizedRecord]
    errors: list[str] = field(default_factory=list)

    @property
    def git_ranges_skipped(self) -> int:
        return sum(record.git_ranges_skipped for record in self.records)


@dataclass
class SourceReport:
    source: str
    status: str
    new: int
    changed: int
    unchanged: int
    errors: list[str] = field(default_factory=list)
    git_ranges_skipped: int = 0

    def summary(self) -> str:
        base = (
            f"{self.source}: {self.status} "
            f"{self.new} new, {self.changed} changed, {self.unchanged} unchanged"
        )
        if self.git_ranges_skipped:
            base += f" git_ranges_skipped={self.git_ranges_skipped}"
        if self.errors:
            base += f" errors={len(self.errors)}"
        return base


def snapshot_file(directory: Path, name: str) -> Path | None:
    plain = directory / name
    compressed = directory / f"{name}.gz"
    if plain.is_file():
        return plain
    if compressed.is_file():
        return compressed
    return None


def load_json_path(path: Path) -> tuple[object | None, str | None]:
    try:
        raw = path.read_bytes()
        if path.name.endswith(".gz"):
            raw = gzip.decompress(raw)
    except (OSError, gzip.BadGzipFile, EOFError) as exc:
        return None, f"{path.name}: {exc.__class__.__name__}"
    if not raw.strip():
        return None, f"{path.name}: empty"
    try:
        return json.loads(raw), None
    except json.JSONDecodeError:
        return None, f"{path.name}: JSONDecodeError"


def file_time(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)


def modified_after(path: Path, moment: datetime | None) -> bool:
    """True when `path` was modified strictly after `moment`."""
    if moment is None:
        return False
    return file_time(path) > moment


def partition_recent(paths: list[Path], skip_newer_than: datetime | None) -> tuple[list[Path], list[str]]:
    """Split paths into ones safe to read and names still being written."""
    kept: list[Path] = []
    skipped: list[str] = []
    for path in paths:
        if modified_after(path, skip_newer_than):
            skipped.append(path.name)
        else:
            kept.append(path)
    return kept, skipped


class Http:
    """One source's HTTP client. `calls` counts attempts, including retries."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.BaseTransport | None = None,
        min_interval: float = 0.0,
        sleep=time.sleep,
    ) -> None:
        self.settings = settings
        self.min_interval = min_interval
        self.sleep = sleep
        self.calls = 0
        self._last = 0.0
        self.client = httpx.Client(
            transport=transport,
            headers={"User-Agent": settings.user_agent(), "Accept": "application/json"},
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
        )

    def close(self) -> None:
        self.client.close()

    def get_json(self, url: str, headers: dict[str, str] | None = None) -> object:
        return self._json("GET", url, headers=headers, body=None)

    def post_json(self, url: str, body: dict, headers: dict[str, str] | None = None) -> object:
        return self._json("POST", url, headers=headers, body=body)

    def _json(self, method: str, url: str, headers: dict[str, str] | None, body: dict | None) -> object:
        response = self.request(method, url, headers=headers, body=body)
        try:
            return response.json()
        except json.JSONDecodeError as exc:
            raise SourceError(f"HTTP {response.status_code} was not JSON") from exc

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: dict | None = None,
    ) -> httpx.Response:
        last = "no response"
        for attempt in range(3):
            self._pace()
            self.calls += 1
            try:
                response = self.client.request(method, url, headers=headers, json=body)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last = exc.__class__.__name__
                if attempt < 2:
                    self.sleep(self._backoff(attempt, None))
                    continue
                raise SourceError(self.settings.redact(last)) from exc
            if response.status_code in RETRY_STATUS and attempt < 2:
                last = f"HTTP {response.status_code}"
                self.sleep(self._backoff(attempt, response))
                continue
            if response.status_code >= 400:
                raise SourceError(self.settings.redact(f"HTTP {response.status_code}"))
            return response
        raise SourceError(self.settings.redact(last))

    def _pace(self) -> None:
        if self.min_interval <= 0:
            return
        now = time.monotonic()
        if self._last:
            remaining = self.min_interval - (now - self._last)
            if remaining > 0:
                self.sleep(remaining)
        self._last = time.monotonic()

    @staticmethod
    def _backoff(attempt: int, response: httpx.Response | None) -> float:
        if response is not None:
            retry_after = response.headers.get("retry-after")
            if retry_after:
                try:
                    parsed = float(retry_after)
                except ValueError:
                    parsed = 0
                if 0 < parsed <= 120:
                    return parsed
        return float(2 ** (attempt + 1))


class Collector:
    source = ""
    interval = 0.2

    def collect(
        self,
        settings: Settings,
        http: Http | None = None,
        window: tuple[str, str] | None = None,
    ) -> SourceBatch:
        if self._disabled(settings):
            return SourceBatch(self.source, "disabled", [])
        if settings.sample_mode:
            return self._snapshot_batch(settings)
        client = http or Http(settings, min_interval=self._interval(settings))
        owns_client = http is None
        try:
            raws = self.fetch_live(settings, client, window)
            records = [self.normalize(raw) for raw in raws]
            return SourceBatch(self.source, "ok", records)
        except SourceError as exc:
            fallback = self._snapshot_batch(settings)
            if fallback.status == "failed" and not fallback.records:
                fallback.errors.insert(0, settings.redact(str(exc)))
                return fallback
            fallback.status = "degraded"
            fallback.errors.insert(0, settings.redact(str(exc)))
            return fallback
        finally:
            if owns_client:
                client.close()

    def fetch_live(
        self,
        settings: Settings,
        http: Http,
        window: tuple[str, str] | None,
    ) -> list[RawRecord]:
        raise SourceError(f"{self.source} has no live fetch")

    def read_snapshot(
        self,
        settings: Settings,
        *,
        skip_newer_than: datetime | None = None,
    ) -> tuple[list[RawRecord], list[str]]:
        raise SourceError(f"{self.source} has no snapshot reader")

    def normalize(self, raw: RawRecord) -> NormalizedRecord:
        raise SourceError(f"{self.source} has no normaliser")

    def _snapshot_batch(self, settings: Settings) -> SourceBatch:
        try:
            raws, errors = self.read_snapshot(settings)
        except SourceError as exc:
            return SourceBatch(self.source, "failed", [], [settings.redact(str(exc))])
        records = [self.normalize(raw) for raw in raws]
        status = "ok" if records or not errors else "failed"
        return SourceBatch(self.source, status, records, errors)

    def _disabled(self, settings: Settings) -> bool:
        disabled = settings.disabled_sources()
        if self.source in disabled:
            return True
        return self.source == "cve_org" and "cve" in disabled

    def _interval(self, settings: Settings) -> float:
        if self.source == "ghsa" and not settings.github_token:
            return 61.0
        if self.source == "nvd":
            return 0.6 if settings.nvd_api_key else 6.0
        return self.interval


def index_rows(rows: list[AffectedRow]) -> None:
    """Number ranges that share the affected primary key, starting at 0."""
    seen: dict[tuple[str, str, str, str], int] = {}
    for row in rows:
        key = (row.vuln_id, row.ecosystem, row.package, row.range_type)
        row.range_index = seen.get(key, 0)
        seen[key] = row.range_index + 1


def dedupe_severity(rows: list[SeverityRow]) -> list[SeverityRow]:
    kept: list[SeverityRow] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        version = row.version or ""
        row.version = version
        key = (row.vuln_id, row.source, version)
        if key in seen:
            suffix = 2
            while (row.vuln_id, f"{row.source}:{suffix}", version) in seen:
                suffix += 1
            row.source = f"{row.source}:{suffix}"
            key = (row.vuln_id, row.source, version)
        seen.add(key)
        kept.append(row)
    return kept
