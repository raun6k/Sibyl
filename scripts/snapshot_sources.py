#!/usr/bin/env python3
"""Fetch raw public vulnerability responses for the sample window.

Saves response bodies as returned. Does not normalise them.
Window defaults are fixed so a rerun is comparable with the previous one.

    uv run scripts/snapshot_sources.py
    uv run scripts/snapshot_sources.py --since 2026-10-09T00:00:00Z --until 2026-10-23T00:00:00Z
    uv run scripts/snapshot_sources.py --force
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"
SBOM_DIR = ROOT / "data" / "sample" / "sboms"
SNAPSHOT_DIR = ROOT / "data" / "sample" / "snapshots"

DEFAULT_SINCE = "2026-10-09T00:00:00Z"
DEFAULT_UNTIL = "2026-10-23T00:00:00Z"
SERVICES = ("checkout-api", "merchant-portal", "reporting-worker", "internal-admin")
SOURCE_ORDER = ("osv", "ghsa", "kev", "epss", "nvd", "cve", "euvd")

OSV_BATCH = 100
EPSS_BATCH = 100
NVD_PAGE = 2000
GZIP_OVER = 5 * 1024 * 1024
MAX_PAGES = 50
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
GHSA_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
GHSA_URL = "https://api.github.com/advisories"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_URL = "https://cveawg.mitre.org/api/cve/{id}"
EUVD_EXPLOITED_URL = "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities"
EUVD_ID_URL = "https://euvdservices.enisa.europa.eu/api/enisaid"
EPSS_URL = "https://api.first.org/data/v1/epss"
GITHUB_API_VERSION = "2026-03-10"


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def load_env(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if " #" in value:
            value = value.split(" #", 1)[0].strip()
        values[key.strip()] = value
    return values


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def stamp(moment: datetime | None = None) -> str:
    current = moment or datetime.now(timezone.utc)
    return current.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def nvd_stamp(value: str) -> str:
    return parse_time(value).strftime("%Y-%m-%dT%H:%M:%S.000")


def in_window(vuln: dict, since: datetime, until: datetime) -> bool:
    for key in ("modified", "published"):
        raw = vuln.get(key)
        if not raw or not isinstance(raw, str):
            continue
        try:
            moment = parse_time(raw)
        except ValueError:
            continue
        if since <= moment < until:
            return True
    return False


def public_url(url: str) -> str:
    parts = urlsplit(url)
    hostname = parts.hostname or ""
    if parts.port and parts.port not in (80, 443):
        netloc = f"{hostname}:{parts.port}"
    else:
        netloc = hostname
    query = [
        (key, val)
        for key, val in parse_qsl(parts.query, keep_blank_values=True)
        if key.lower() not in {"apikey", "api_key", "token", "access_token", "key"}
    ]
    return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query), ""))


def safe_text(text: str, secrets: list[str]) -> str:
    cleaned = text
    for secret in secrets:
        if secret and len(secret) >= 4:
            cleaned = cleaned.replace(secret, "[redacted]")
    return cleaned[:400]


def flatten(components: list | None) -> list[dict]:
    found: list[dict] = []
    for component in components or []:
        found.append(component)
        found.extend(flatten(component.get("components")))
    return found


def load_purls() -> dict[str, set[str]]:
    """Map each component purl to the sample services that ship it."""
    found: dict[str, set[str]] = {}
    for service in SERVICES:
        document = json.loads((SBOM_DIR / f"{service}.cdx.json").read_text(encoding="utf-8"))
        for component in flatten(document.get("components")):
            purl = component.get("purl") or ""
            if purl.startswith("pkg:"):
                found.setdefault(purl, set()).add(service)
    return found


def cve_ids_from_osv(vuln: dict) -> set[str]:
    found: set[str] = set()
    identifier = vuln.get("id") or ""
    if CVE_RE.match(identifier):
        found.add(identifier)
    for alias in vuln.get("aliases") or []:
        if isinstance(alias, str) and CVE_RE.match(alias):
            found.add(alias)
    return found


def count_records(payload: bytes, kind: str) -> int | None:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return None
    if kind == "osv-batch":
        return sum(len(item.get("vulns") or []) for item in data.get("results") or [])
    if kind == "list":
        return len(data) if isinstance(data, list) else None
    if kind == "kev":
        vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
        return len(vulns) if isinstance(vulns, list) else None
    if kind == "epss":
        rows = data.get("data") if isinstance(data, dict) else None
        return len(rows) if isinstance(rows, list) else None
    if kind == "nvd":
        vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
        return len(vulns) if isinstance(vulns, list) else None
    if kind == "one":
        return 1 if isinstance(data, dict) else 0
    if kind == "euvd-list":
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            for key in ("vulnerabilities", "items", "content", "data"):
                if isinstance(data.get(key), list):
                    return len(data[key])
        return 1 if isinstance(data, dict) else None
    return None


def read_stored(path: Path) -> bytes:
    raw = path.read_bytes()
    if path.name.endswith(".gz"):
        return gzip.decompress(raw)
    return raw


@dataclass
class RequestRecord:
    url: str
    method: str
    fetched_at: str | None = None
    http_status: int | None = None
    file: str | None = None
    record_count: int | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    error: str | None = None
    purls: list[str] | None = None
    next_url: str | None = None
    compressed: bool = False

    def as_dict(self) -> dict:
        payload = {
            "url": self.url,
            "method": self.method,
            "fetched_at": self.fetched_at,
            "http_status": self.http_status,
            "file": self.file,
            "record_count": self.record_count,
            "bytes": self.size_bytes,
            "sha256": self.sha256,
            "error": self.error,
        }
        if self.compressed:
            payload["compressed"] = True
        if self.purls is not None:
            payload["purls"] = self.purls
        if self.next_url:
            payload["next_url"] = self.next_url
        return payload


@dataclass
class SourceResult:
    name: str
    requests: list[RequestRecord] = field(default_factory=list)
    error: str | None = None
    note: str | None = None

    def as_dict(self) -> dict:
        payload = {
            "error": self.error,
            "requests": [item.as_dict() for item in self.requests],
        }
        if self.note:
            payload["note"] = self.note
        return payload


class Pace:
    def __init__(self, min_interval: float, hourly_cap: int | None = None, label: str = "") -> None:
        self.min_interval = min_interval
        self.hourly_cap = hourly_cap
        self.label = label
        self.last = 0.0
        self.stamps: list[float] = []

    def wait(self) -> None:
        now = time.monotonic()
        if self.hourly_cap is not None:
            self.stamps = [item for item in self.stamps if now - item < 3600]
            if len(self.stamps) >= self.hourly_cap:
                sleep_for = 3600 - (now - self.stamps[0]) + 1
                log(f"{self.label}: waiting {sleep_for:.0f}s to stay under {self.hourly_cap}/hour")
                time.sleep(sleep_for)
                now = time.monotonic()
        if self.last and now - self.last < self.min_interval:
            time.sleep(self.min_interval - (now - self.last))
        self.last = time.monotonic()
        self.stamps.append(self.last)


class Fetcher:
    def __init__(self, email: str, secrets: list[str]) -> None:
        self.secrets = secrets
        self.client = httpx.Client(
            headers={"User-Agent": f"sibyl ({email})", "Accept": "application/json"},
            timeout=httpx.Timeout(30.0, read=180.0),
            follow_redirects=True,
        )

    def close(self) -> None:
        self.client.close()

    def fetch(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict | None = None,
        pace: Pace | None = None,
    ) -> httpx.Response:
        last_error = "no response"
        response: httpx.Response | None = None
        for attempt in range(3):
            if pace is not None:
                pace.wait()
            try:
                response = self.client.request(method, url, headers=headers, json=json_body)
            except httpx.HTTPError as exc:
                last_error = exc.__class__.__name__
                if attempt < 2:
                    delay = 2 ** (attempt + 1)
                    log(f"retry {attempt + 1} {method} {public_url(url)} after {last_error} ({delay}s)")
                    time.sleep(delay)
                    continue
                raise RuntimeError(f"{method} {public_url(url)} {last_error}") from None
            if self._retryable(response) and attempt < 2:
                delay = self._delay(response, attempt)
                log(
                    f"retry {attempt + 1} {method} {public_url(url)} "
                    f"HTTP {response.status_code} ({delay}s)"
                )
                time.sleep(delay)
                continue
            return response
        if response is not None:
            return response
        raise RuntimeError(f"{method} {public_url(url)} {last_error}")

    @staticmethod
    def _retryable(response: httpx.Response) -> bool:
        if response.status_code in {429, 500, 502, 503, 504}:
            return True
        if response.status_code == 403 and "rate limit" in response.text.lower():
            return True
        return False

    @staticmethod
    def _delay(response: httpx.Response, attempt: int) -> float:
        reset = response.headers.get("x-ratelimit-reset")
        if reset:
            try:
                wait = float(reset) - time.time() + 1
            except ValueError:
                wait = 0
            if 0 < wait <= 3700:
                return wait
        retry_after = response.headers.get("retry-after")
        if retry_after:
            try:
                parsed = float(retry_after)
            except ValueError:
                parsed = 0
            if 0 < parsed <= 3700:
                return parsed
        return float(2 ** (attempt + 1))


class Store:
    def __init__(self, root: Path, force: bool, prior: dict) -> None:
        self.root = root
        self.force = force
        self.prior = prior
        self.root.mkdir(parents=True, exist_ok=True)

    def source_dir(self, source: str) -> Path:
        path = self.root / source
        path.mkdir(parents=True, exist_ok=True)
        return path

    def existing(self, source: str, filename: str) -> Path | None:
        directory = self.root / source
        plain = directory / filename
        gzipped = directory / f"{filename}.gz"
        if plain.is_file():
            return plain
        if gzipped.is_file():
            return gzipped
        return None

    def remember(self, source: str, filename: str) -> RequestRecord | None:
        previous = self.prior.get(source) or {}
        for item in previous.get("requests") or []:
            stored = item.get("file") or ""
            if stored == filename or stored == f"{filename}.gz":
                record = RequestRecord(
                    url=item.get("url") or "",
                    method=item.get("method") or "GET",
                    fetched_at=item.get("fetched_at"),
                    http_status=item.get("http_status"),
                    file=stored,
                    record_count=item.get("record_count"),
                    size_bytes=item.get("bytes"),
                    sha256=item.get("sha256"),
                    error=item.get("error"),
                    purls=item.get("purls"),
                    next_url=item.get("next_url"),
                    compressed=bool(item.get("compressed")),
                )
                path = self.root / source / stored
                if path.is_file():
                    digest, size = hash_file(path)
                    record.sha256 = digest
                    record.size_bytes = size
                    record.record_count = count_records(read_stored(path), kind_for(filename))
                return record
        path = self.existing(source, filename)
        if path is None:
            return None
        digest, size = hash_file(path)
        return RequestRecord(
            url="",
            method="GET",
            fetched_at=stamp(datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)),
            http_status=None,
            file=path.name,
            record_count=count_records(read_stored(path), kind_for(filename)),
            size_bytes=size,
            sha256=digest,
            error=None,
            compressed=path.name.endswith(".gz"),
        )

    def save(self, source: str, filename: str, payload: bytes, kind: str) -> tuple[Path, int]:
        directory = self.source_dir(source)
        compressed = len(payload) > GZIP_OVER
        stored_name = f"{filename}.gz" if compressed else filename
        path = directory / stored_name
        if compressed:
            path.write_bytes(gzip.compress(payload))
        else:
            path.write_bytes(payload)
        return path, count_records(payload, kind) or 0


def hash_file(path: Path) -> tuple[str, int]:
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


def kind_for(filename: str) -> str:
    name = filename.removesuffix(".gz")
    if name.startswith("querybatch-"):
        return "osv-batch"
    if name.startswith("advisories-"):
        return "list"
    if name == "known_exploited_vulnerabilities.json":
        return "kev"
    if name.startswith("batch-"):
        return "epss"
    if name.startswith("window-"):
        return "nvd"
    if name == "exploitedvulnerabilities.json":
        return "euvd-list"
    return "one"


def load_prior(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return document.get("sources") or {}


def next_link(response: httpx.Response) -> str | None:
    header = response.headers.get("link")
    if not header:
        return None
    for part in header.split(","):
        if 'rel="next"' not in part:
            continue
        url = part.split(";", 1)[0].strip().strip("<>")
        if url:
            return url
    return None


def is_rate_limited(response: httpx.Response) -> bool:
    if response.status_code == 429:
        return True
    return response.status_code == 403 and "rate limit" in response.text.lower()


class Snapshot:
    def __init__(self, since: str, until: str, force: bool, env: dict[str, str]) -> None:
        email = env.get("CONTACT_EMAIL", "").strip()
        if not email:
            raise SystemExit(
                "CONTACT_EMAIL is empty in .env. Set it before fetching. "
                'It is sent as User-Agent "sibyl (<email>)" and is not written into snapshots.'
            )
        self.since = since
        self.until = until
        self.since_dt = parse_time(since)
        self.until_dt = parse_time(until)
        self.force = force
        self.nvd_key = env.get("NVD_API_KEY", "").strip()
        self.github_token = env.get("GITHUB_TOKEN", "").strip()
        self.secrets = [email, self.nvd_key, self.github_token]
        self.fetcher = Fetcher(email, self.secrets)
        self.store = Store(SNAPSHOT_DIR, force, load_prior(SNAPSHOT_DIR / "manifest.json"))
        self.sources = {name: SourceResult(name) for name in SOURCE_ORDER}
        self.purl_services = load_purls()
        self.vuln_services: dict[str, set[str]] = {}
        self.vulns: dict[str, dict] = {}
        self.ghsa_ids: set[str] = set()
        self.ghsa_window_cves: set[str] = set()
        self.kev_cves: set[str] = set()
        self.nvd_window_cves: set[str] = set()
        self._last_link: str | None = None

    def close(self) -> None:
        self.fetcher.close()

    def redact(self, text: str) -> str:
        return safe_text(text, self.secrets)

    def take(
        self,
        source: str,
        method: str,
        url: str,
        filename: str,
        kind: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict | None = None,
        pace: Pace | None = None,
        purls: list[str] | None = None,
        save_404: bool = False,
    ) -> tuple[bytes | None, bool]:
        """Return (body, stop_source). body is None when the call failed or was skipped without a file."""
        result = self.sources[source]
        clean_url = public_url(url)
        if not self.force:
            existing = self.store.existing(source, filename)
            if existing is not None:
                record = self.store.remember(source, filename)
                if record is None:
                    record = RequestRecord(url=clean_url, method=method, file=existing.name)
                if not record.url:
                    record.url = clean_url
                if purls is not None:
                    record.purls = purls
                result.requests.append(record)
                self._last_link = public_url(record.next_url) if record.next_url else None
                log(f"{source}: skip {existing.name}")
                try:
                    return read_stored(existing), False
                except (OSError, gzip.BadGzipFile, EOFError) as exc:
                    record.error = self.redact(f"unreadable existing file: {exc.__class__.__name__}")
                    return None, False
        try:
            response = self.fetcher.fetch(
                method, url, headers=headers, json_body=json_body, pace=pace
            )
        except RuntimeError as exc:
            result.requests.append(
                RequestRecord(url=clean_url, method=method, fetched_at=stamp(), error=self.redact(str(exc)), purls=purls)
            )
            log(f"{source}: {self.redact(str(exc))}")
            self._last_link = None
            return None, True
        status = response.status_code
        link = next_link(response)
        self._last_link = public_url(link) if link else None
        keep = 200 <= status < 300 or (save_404 and status == 404)
        record = RequestRecord(
            url=clean_url,
            method=method,
            fetched_at=stamp(),
            http_status=status,
            purls=purls,
            error=None if 200 <= status < 300 else f"HTTP {status}",
            next_url=self._last_link,
        )
        if keep:
            path, count = self.store.save(source, filename, response.content, kind)
            digest, size = hash_file(path)
            record.file = path.name
            record.record_count = count
            record.size_bytes = size
            record.sha256 = digest
            record.compressed = path.name.endswith(".gz")
            result.requests.append(record)
            log(f"{source}: {method} {clean_url} -> {path.name} HTTP {status} records={count} bytes={size}")
            return response.content, False
        result.requests.append(record)
        log(f"{source}: {method} {clean_url} HTTP {status}")
        return None, is_rate_limited(response)

    def fetch_osv(self) -> None:
        result = self.sources["osv"]
        purls = sorted(self.purl_services)
        if not purls:
            result.error = "no purls in the sample SBOMs"
            return
        batches = [purls[index : index + OSV_BATCH] for index in range(0, len(purls), OSV_BATCH)]
        pace = Pace(0.2, label="osv")
        matched: dict[str, set[str]] = {}
        log(f"osv: {len(purls)} purls in {len(batches)} batches")
        for index, batch in enumerate(batches):
            body = {"queries": [{"package": {"purl": purl}} for purl in batch]}
            payload, stop = self.take(
                "osv",
                "POST",
                OSV_BATCH_URL,
                f"querybatch-{index:03d}.json",
                "osv-batch",
                json_body=body,
                pace=pace,
                purls=batch,
            )
            if stop:
                result.error = result.error or "stopped after a failed querybatch"
                break
            if not payload:
                continue
            try:
                parsed = json.loads(payload)
            except json.JSONDecodeError:
                result.error = f"querybatch-{index:03d} was not JSON"
                continue
            results = parsed.get("results") or []
            if len(results) != len(batch):
                result.error = (
                    f"querybatch-{index:03d} returned {len(results)} results for {len(batch)} queries"
                )
            for purl, item in zip(batch, results):
                for vuln in item.get("vulns") or []:
                    identifier = vuln.get("id")
                    if not identifier:
                        continue
                    matched.setdefault(identifier, set()).update(self.purl_services.get(purl, set()))
                    if GHSA_RE.match(identifier):
                        self.ghsa_ids.add(identifier)
        identifiers = sorted(matched)
        log(f"osv: {len(identifiers)} unique vuln ids")
        consecutive = 0
        for number, identifier in enumerate(identifiers, start=1):
            payload, stop = self.take(
                "osv",
                "GET",
                OSV_VULN_URL.format(id=identifier),
                f"vuln-{identifier}.json",
                "one",
                pace=pace,
                save_404=True,
            )
            if payload and stop is False:
                try:
                    document = json.loads(payload)
                except json.JSONDecodeError:
                    document = None
                if isinstance(document, dict) and document.get("id"):
                    self.vulns[document["id"]] = document
                    self.vuln_services[document["id"]] = matched.get(document["id"], set())
                    if GHSA_RE.match(document["id"]):
                        self.ghsa_ids.add(document["id"])
                    consecutive = 0
                else:
                    consecutive += 1
            else:
                consecutive += 1
            if number % 25 == 0 or number == len(identifiers):
                log(f"osv: vuln details {number}/{len(identifiers)}")
            if stop or consecutive >= 3:
                result.error = result.error or "stopped after repeated vuln lookup failures"
                break
        if not self.vulns and identifiers and result.error is None:
            result.error = "querybatch returned ids but no vuln document could be read"

    def fetch_ghsa(self) -> None:
        result = self.sources["ghsa"]
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
            pace = Pace(0.8, label="ghsa")
            log("ghsa: using GITHUB_TOKEN (value not printed)")
        else:
            pace = Pace(61.0, hourly_cap=58, label="ghsa")
            log("ghsa: no GITHUB_TOKEN, staying under 60 requests/hour")
        seen: set[str] = set()
        modified = f"{self.since}..{self.until}"
        for ecosystem in ("pip", "npm"):
            url = GHSA_URL + "?" + urlencode(
                {
                    "type": "reviewed",
                    "ecosystem": ecosystem,
                    "modified": modified,
                    "per_page": 100,
                }
            )
            for page in range(MAX_PAGES):
                payload, stop = self.take(
                    "ghsa",
                    "GET",
                    url,
                    f"advisories-{ecosystem}-{page:03d}.json",
                    "list",
                    headers=headers,
                    pace=pace,
                )
                if stop:
                    result.error = result.error or f"stopped while listing {ecosystem} advisories"
                    return
                if not payload:
                    last = result.requests[-1] if result.requests else None
                    if last is not None and last.error:
                        result.error = result.error or f"{ecosystem} page {page}: {last.error}"
                    break
                try:
                    rows = json.loads(payload)
                except json.JSONDecodeError:
                    result.error = f"{ecosystem} page {page} was not JSON"
                    break
                if not isinstance(rows, list) or not rows:
                    break
                for advisory in rows:
                    if not isinstance(advisory, dict):
                        continue
                    identifier = advisory.get("ghsa_id")
                    if isinstance(identifier, str):
                        seen.add(identifier)
                    cve_id = advisory.get("cve_id")
                    if isinstance(cve_id, str) and CVE_RE.match(cve_id):
                        self.ghsa_window_cves.add(cve_id)
                if len(rows) < 100:
                    break
                link = self._last_link
                self._last_link = None
                next_filename = f"advisories-{ecosystem}-{page + 1:03d}.json"
                if not link and self.store.existing("ghsa", next_filename):
                    prior = self.store.remember("ghsa", next_filename)
                    link = prior.url if prior and prior.url else None
                if not link:
                    if len(rows) == 100:
                        result.error = (
                            result.error
                            or f"{ecosystem} page {page} was full and had no next link; later pages were not fetched"
                        )
                    break
                url = link
            else:
                result.error = result.error or f"{ecosystem} exceeded {MAX_PAGES} pages"
        missing = sorted(self.ghsa_ids - seen)
        log(f"ghsa: window advisories {len(seen)}, extra OSV ids {len(missing)}")
        if missing and not self.github_token:
            log(f"ghsa: about {len(missing)} more requests, roughly {len(missing)} minutes at 60/hour")
        consecutive = 0
        for identifier in missing:
            payload, stop = self.take(
                "ghsa",
                "GET",
                f"{GHSA_URL}/{identifier}",
                f"advisory-{identifier}.json",
                "one",
                headers=headers,
                pace=pace,
                save_404=True,
            )
            if stop:
                result.error = result.error or "stopped while fetching OSV GHSA ids"
                return
            if payload:
                consecutive = 0
                try:
                    advisory = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                cve_id = advisory.get("cve_id") if isinstance(advisory, dict) else None
                if isinstance(cve_id, str) and CVE_RE.match(cve_id):
                    # Individual OSV lookups are not part of the window list.
                    pass
            else:
                consecutive += 1
                if consecutive >= 3:
                    result.error = result.error or "stopped after repeated GHSA lookup failures"
                    return

    def fetch_kev(self) -> None:
        payload, stop = self.take(
            "kev",
            "GET",
            KEV_URL,
            "known_exploited_vulnerabilities.json",
            "kev",
            pace=Pace(0.0, label="kev"),
        )
        if stop or not payload:
            self.sources["kev"].error = self.sources["kev"].error or "KEV catalog was not fetched"
            return
        try:
            document = json.loads(payload)
        except json.JSONDecodeError:
            self.sources["kev"].error = "KEV response was not JSON"
            return
        for item in document.get("vulnerabilities") or []:
            cve_id = item.get("cveID") if isinstance(item, dict) else None
            if isinstance(cve_id, str) and CVE_RE.match(cve_id):
                self.kev_cves.add(cve_id)
        log(f"kev: {len(self.kev_cves)} CVE ids")

    def fetch_epss(self) -> None:
        matched = self.matched_cves()
        wanted = sorted(matched | self.ghsa_window_cves)
        self.sources["epss"].note = (
            "CVE ids from the OSV matched set and from GHSA advisories modified in the window. "
            "The NVD window is fetched after EPSS, so those CVE ids are not in this snapshot."
        )
        if not wanted:
            self.sources["epss"].note += " No CVE ids to score."
            log("epss: no CVE ids")
            return
        log(
            f"epss: {len(wanted)} CVE ids "
            f"(matched {len(matched)}, ghsa-window {len(self.ghsa_window_cves)})"
        )
        pace = Pace(0.4, label="epss")
        consecutive = 0
        for index in range(0, len(wanted), EPSS_BATCH):
            batch = wanted[index : index + EPSS_BATCH]
            url = f"{EPSS_URL}?cve={','.join(batch)}"
            payload, stop = self.take(
                "epss",
                "GET",
                url,
                f"batch-{index // EPSS_BATCH:03d}.json",
                "epss",
                pace=pace,
            )
            if stop or not payload:
                consecutive += 1
                if stop or consecutive >= 3:
                    self.sources["epss"].error = self.sources["epss"].error or "stopped during EPSS batches"
                    return
            else:
                consecutive = 0

    def fetch_nvd(self) -> None:
        result = self.sources["nvd"]
        headers = {"apiKey": self.nvd_key} if self.nvd_key else None
        if self.nvd_key:
            pace = Pace(0.6, label="nvd")
            log("nvd: using NVD_API_KEY (value not printed)")
        else:
            pace = Pace(6.0, label="nvd")
            log("nvd: no NVD_API_KEY, 6s between calls")
        start = 0
        for page in range(MAX_PAGES):
            url = NVD_URL + "?" + urlencode(
                {
                    "lastModStartDate": nvd_stamp(self.since),
                    "lastModEndDate": nvd_stamp(self.until),
                    "resultsPerPage": NVD_PAGE,
                    "startIndex": start,
                }
            )
            payload, stop = self.take(
                "nvd",
                "GET",
                url,
                f"window-{page:03d}.json",
                "nvd",
                headers=headers,
                pace=pace,
            )
            if stop or not payload:
                result.error = result.error or "stopped during the NVD window"
                break
            try:
                document = json.loads(payload)
            except json.JSONDecodeError:
                result.error = f"window page {page} was not JSON"
                break
            for item in document.get("vulnerabilities") or []:
                cve = (item.get("cve") or {}).get("id") if isinstance(item, dict) else None
                if isinstance(cve, str) and CVE_RE.match(cve):
                    self.nvd_window_cves.add(cve)
            total = int(document.get("totalResults") or 0)
            per_page = int(document.get("resultsPerPage") or NVD_PAGE)
            start += per_page
            log(f"nvd: window page {page} total={total} collected={len(self.nvd_window_cves)}")
            if per_page <= 0 or start >= total:
                break
        else:
            result.error = result.error or f"NVD window exceeded {MAX_PAGES} pages"
        missing = sorted(self.matched_cves() - self.nvd_window_cves)
        log(f"nvd: {len(missing)} matched CVE ids outside the window")
        consecutive = 0
        for identifier in missing:
            payload, stop = self.take(
                "nvd",
                "GET",
                f"{NVD_URL}?cveId={identifier}",
                f"cve-{identifier}.json",
                "nvd",
                headers=headers,
                pace=pace,
                save_404=True,
            )
            if stop:
                result.error = result.error or "stopped during matched CVE lookups"
                return
            if payload:
                consecutive = 0
            else:
                consecutive += 1
                if consecutive >= 3:
                    result.error = result.error or "stopped after repeated NVD CVE lookup failures"
                    return

    def fetch_cve_org(self) -> None:
        identifiers = sorted(self.matched_cves())
        if not identifiers:
            self.sources["cve"].note = "No matched CVE ids, so the per-id CVE.org fetch was skipped."
            log("cve: no matched CVE ids")
            return
        pace = Pace(0.3, label="cve")
        consecutive = 0
        log(f"cve: {len(identifiers)} matched CVE ids")
        for identifier in identifiers:
            payload, stop = self.take(
                "cve",
                "GET",
                CVE_URL.format(id=identifier),
                f"{identifier}.json",
                "one",
                pace=pace,
                save_404=True,
            )
            if stop:
                self.sources["cve"].error = self.sources["cve"].error or "stopped during CVE.org lookups"
                return
            if payload:
                consecutive = 0
            else:
                consecutive += 1
                if consecutive >= 3:
                    self.sources["cve"].error = (
                        self.sources["cve"].error or "stopped after repeated CVE.org lookup failures"
                    )
                    return

    def fetch_euvd(self) -> None:
        result = self.sources["euvd"]
        payload, stop = self.take(
            "euvd",
            "GET",
            EUVD_EXPLOITED_URL,
            "exploitedvulnerabilities.json",
            "euvd-list",
            pace=Pace(0.5, label="euvd"),
        )
        if stop:
            result.error = result.error or "exploited-vulnerabilities list was not fetched"
        identifiers = sorted(self.matched_cves())
        if not identifiers:
            result.note = "No matched CVE ids for per-CVE EUVD lookups."
            return
        log(f"euvd: {len(identifiers)} per-CVE lookups")
        pace = Pace(0.5, label="euvd")
        consecutive = 0
        for identifier in identifiers:
            payload, stop = self.take(
                "euvd",
                "GET",
                f"{EUVD_ID_URL}?id={identifier}",
                f"{identifier}.json",
                "one",
                pace=pace,
                save_404=True,
            )
            if stop:
                result.error = result.error or "stopped during EUVD per-CVE lookups"
                return
            if payload:
                consecutive = 0
            else:
                consecutive += 1
                if consecutive >= 3:
                    result.error = result.error or "stopped after repeated EUVD lookup failures"
                    return

    def matched_cves(self) -> set[str]:
        found: set[str] = set()
        for vuln in self.vulns.values():
            found.update(cve_ids_from_osv(vuln))
        return found

    def report(self) -> dict:
        per_service = {service: 0 for service in SERVICES}
        in_window = 0
        for identifier, services in self.vuln_services.items():
            for service in services:
                if service in per_service:
                    per_service[service] += 1
            document = self.vulns.get(identifier)
            if document and in_window_doc(document, self.since_dt, self.until_dt):
                in_window += 1
        matched_cves = self.matched_cves()
        in_kev = len(matched_cves & self.kev_cves) if self.kev_cves or self.sources["kev"].error is None else None
        if self.sources["kev"].error:
            in_kev = None
        return {
            "window": {
                "since": self.since,
                "until": self.until,
                "comparison": "modified or published, since inclusive, until exclusive",
            },
            "matched_total": len(self.vuln_services),
            "per_service": per_service,
            "in_window": in_window,
            "matched_cves": len(matched_cves),
            "matched_cves_in_kev": in_kev,
        }

    def write_manifest(self, report: dict) -> None:
        document = {
            "window": {"since": self.since, "until": self.until},
            "generated_at": stamp(),
            "sources": {name: self.sources[name].as_dict() for name in SOURCE_ORDER},
            "match_report": report,
        }
        path = SNAPSHOT_DIR / "manifest.json"
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        log(f"wrote {path}")


def in_window_doc(vuln: dict, since: datetime, until: datetime) -> bool:
    return in_window(vuln, since, until)


def print_report(report: dict, sources: dict[str, SourceResult]) -> None:
    print("match report")
    window = report["window"]
    print(f"  window: {window['since']} .. {window['until']} ({window['comparison']})")
    print(f"  matched vulns overall: {report['matched_total']}")
    for service, count in report["per_service"].items():
        print(f"  {service}: {count}")
    print(f"  matched vulns in window: {report['in_window']}")
    kev = report["matched_cves_in_kev"]
    if kev is None:
        print("  matched CVEs in KEV: unavailable")
    else:
        print(f"  matched CVEs in KEV: {kev}")
    print(f"  matched CVE ids: {report['matched_cves']}")
    failures = [(name, item.error) for name, item in sources.items() if item.error]
    if failures:
        print("  source errors:")
        for name, error in failures:
            print(f"    {name}: {error}")
    else:
        print("  source errors: none")


def directory_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for file in path.rglob("*"):
        if file.is_file():
            total += file.stat().st_size
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch raw sample sample snapshots for a fixed window.")
    parser.add_argument("--since", default=DEFAULT_SINCE)
    parser.add_argument("--until", default=DEFAULT_UNTIL)
    parser.add_argument("--force", action="store_true", help="Refetch files that already exist.")
    args = parser.parse_args()
    parse_time(args.since)
    parse_time(args.until)
    snapshot = Snapshot(args.since, args.until, args.force, load_env(ENV_PATH))
    try:
        log(f"window {args.since} .. {args.until}")
        log(f"purls {len(snapshot.purl_services)}")
        for name, method in (
            ("osv", snapshot.fetch_osv),
            ("ghsa", snapshot.fetch_ghsa),
            ("kev", snapshot.fetch_kev),
            ("epss", snapshot.fetch_epss),
            ("nvd", snapshot.fetch_nvd),
            ("cve", snapshot.fetch_cve_org),
            ("euvd", snapshot.fetch_euvd),
        ):
            log(f"== {name} ==")
            try:
                method()
            except Exception as exc:
                message = snapshot.redact(f"{exc.__class__.__name__}: {exc}")
                snapshot.sources[name].error = snapshot.sources[name].error or message
                log(f"{name}: FAILED {message}")
        report = snapshot.report()
        snapshot.write_manifest(report)
        print_report(report, snapshot.sources)
        size = directory_size(SNAPSHOT_DIR)
        print(f"  snapshot bytes: {size}")
    finally:
        snapshot.close()
    report = json.loads((SNAPSHOT_DIR / "manifest.json").read_text(encoding="utf-8"))["match_report"]
    if report["matched_total"] < 20 or report["in_window"] < 10:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
