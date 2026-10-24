"""Copy a frozen subset of the on-disk snapshots into tests/fixtures.

Reads data/sample/snapshots and does not write there. The download that is
filling that directory can keep running. --fetch-missing does at most 12 GETs
for the CVE.org and EUVD records that are not in the snapshot yet.

Re-running the copy step rebuilds tests/fixtures/snapshots/{osv,ghsa,kev,epss,nvd}
from whatever is on disk at that moment. Part E keeps the committed subset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"
SBOM_DIR = ROOT / "data" / "sample" / "sboms"
SNAPSHOT_DIR = ROOT / "data" / "sample" / "snapshots"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "snapshots"
DOC_PATH = ROOT / "tests" / "fixtures" / "snapshots" / "FIXTURES.md"

SERVICES = ("checkout-api", "merchant-portal", "reporting-worker", "internal-admin")
OSV_BATCH = 100
TARGET = 40
MAX_GETS = 12
SIZE_LIMIT = 6 * 1024 * 1024
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

CVE_URL = "https://cveawg.mitre.org/api/cve/{id}"
EUVD_EXPLOITED_URL = "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities"
EUVD_ID_URL = "https://euvdservices.enisa.europa.eu/api/enisaid"

COPIED_SOURCES = ("osv", "ghsa", "kev", "epss", "nvd")


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
        values[key.strip()] = value
    return values


def stamp(moment: datetime | None = None) -> str:
    value = moment or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_stamp(path: Path) -> str:
    moment = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    return stamp(moment)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def flatten(components: list | None) -> list[dict]:
    found: list[dict] = []
    for component in components or []:
        found.append(component)
        found.extend(flatten(component.get("components")))
    return found


def load_purls() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for service in SERVICES:
        document = json.loads((SBOM_DIR / f"{service}.cdx.json").read_text(encoding="utf-8"))
        for component in flatten(document.get("components")):
            purl = component.get("purl") or ""
            if purl.startswith("pkg:"):
                found.setdefault(purl, set()).add(service)
    return found


def read_json(path: Path) -> tuple[bytes, object]:
    last: json.JSONDecodeError | None = None
    for attempt in range(2):
        raw = path.read_bytes()
        try:
            return raw, json.loads(raw)
        except json.JSONDecodeError as exc:
            last = exc
            if attempt == 0:
                time.sleep(0.3)
    raise SystemExit(f"{path} is not complete JSON ({last})")


def eco_type(raw: str | None) -> str | None:
    return {"PyPI": "pypi", "pip": "pypi", "pypi": "pypi", "npm": "npm"}.get(raw or "")


def norm_name(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name.lower())
    return name.lower()


def osv_intervals(document: dict) -> list[tuple]:
    rows: list[tuple] = []
    for affected in document.get("affected") or []:
        package = affected.get("package") or {}
        ecosystem = eco_type(package.get("ecosystem"))
        if not ecosystem:
            continue
        name = norm_name(ecosystem, package.get("name") or "")
        for rng in affected.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            current: dict[str, str | None] = {}
            for event in rng.get("events") or []:
                if "introduced" in event:
                    if current:
                        rows.append(
                            (name, ecosystem, current.get("introduced"), current.get("fixed"), current.get("last_affected"))
                        )
                    current = {"introduced": event.get("introduced")}
                elif "fixed" in event:
                    current["fixed"] = event.get("fixed")
                    rows.append((name, ecosystem, current.get("introduced"), current.get("fixed"), None))
                    current = {}
                elif "last_affected" in event:
                    current["last_affected"] = event.get("last_affected")
                    rows.append((name, ecosystem, current.get("introduced"), None, current.get("last_affected")))
                    current = {}
            if current:
                rows.append(
                    (name, ecosystem, current.get("introduced"), current.get("fixed"), current.get("last_affected"))
                )
    return rows


def parse_ghsa_range(text: str | None) -> list[tuple[str | None, str | None, str | None]]:
    if not text:
        return []
    parsed: list[tuple[str | None, str | None, str | None]] = []
    for part in text.split("||"):
        introduced = fixed = last = None
        for clause in part.split(","):
            match = re.match(r"^\s*(>=|<=|>|<|=)\s*(.+?)\s*$", clause)
            if not match:
                continue
            op, version = match.group(1), match.group(2)
            if op in {">=", ">"}:
                introduced = version
            elif op == "<":
                fixed = version
            elif op == "<=":
                last = version
            elif op == "=":
                introduced = version
                last = version
        parsed.append((introduced, fixed, last))
    return parsed


def ghsa_intervals(row: dict) -> list[tuple]:
    rows: list[tuple] = []
    for vuln in row.get("vulnerabilities") or []:
        package = vuln.get("package") or {}
        ecosystem = eco_type(package.get("ecosystem"))
        if not ecosystem:
            continue
        name = norm_name(ecosystem, package.get("name") or "")
        patched = vuln.get("first_patched_version")
        if isinstance(patched, dict):
            patched = patched.get("identifier") or patched.get("version")
        for introduced, fixed, last in parse_ghsa_range(vuln.get("vulnerable_version_range")):
            rows.append((name, ecosystem, introduced, fixed or (patched if not last else fixed), last))
    return rows


def ranges_differ(osv_doc: dict, ghsa_row: dict | None) -> bool:
    if not ghsa_row:
        return False
    left = {(name, eco, intro or "", fixed or "", last or "") for name, eco, intro, fixed, last in osv_intervals(osv_doc)}
    right = {
        (name, eco, intro or "", fixed or "", last or "")
        for name, eco, intro, fixed, last in ghsa_intervals(ghsa_row)
    }
    packages = {(name, eco) for name, eco, *_rest in left} & {(name, eco) for name, eco, *_rest in right}
    for name, eco in packages:
        osv_set = {item[2:] for item in left if item[0] == name and item[1] == eco}
        ghsa_set = {item[2:] for item in right if item[0] == name and item[1] == eco}
        if osv_set != ghsa_set:
            return True
    return False


def index_ghsa(root: Path) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for path in sorted((root / "ghsa").glob("*.json")):
        _raw, data = read_json(path)
        rows = data if isinstance(data, list) else [data]
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("ghsa_id"), str):
                found[row["ghsa_id"]] = row
    return found


def load_records(root: Path, purl_services: dict[str, set[str]]) -> tuple[list[dict], dict[int, list[str]]]:
    purls = sorted(purl_services)
    batches = [purls[index : index + OSV_BATCH] for index in range(0, len(purls), OSV_BATCH)]
    vuln_services: dict[str, set[str]] = defaultdict(set)
    batch_of: dict[str, int] = {}
    for index, batch in enumerate(batches):
        path = root / "osv" / f"querybatch-{index:03d}.json"
        if not path.is_file():
            continue
        _raw, data = read_json(path)
        results = data.get("results") or []
        if len(results) != len(batch):
            raise SystemExit(
                f"querybatch-{index:03d} has {len(results)} results for {len(batch)} purls"
            )
        for purl, item in zip(batch, results):
            for vuln in item.get("vulns") or []:
                identifier = vuln.get("id")
                if not identifier:
                    continue
                vuln_services[identifier].update(purl_services.get(purl, set()))
                batch_of.setdefault(identifier, index)
    kev = read_json(root / "kev" / "known_exploited_vulnerabilities.json")[1]
    kev_ids = {
        item.get("cveID")
        for item in (kev.get("vulnerabilities") or [])
        if isinstance(item, dict)
    }
    nvd_cves = set()
    for path in (root / "nvd").glob("cve-*.json"):
        nvd_cves.add(path.name.removeprefix("cve-").removesuffix(".json"))
    advisory_ids = {
        path.name.removeprefix("advisory-").removesuffix(".json")
        for path in (root / "ghsa").glob("advisory-*.json")
    }
    ghsa_rows = index_ghsa(root)
    records = []
    for identifier, services in vuln_services.items():
        path = root / "osv" / f"vuln-{identifier}.json"
        if not path.is_file():
            continue
        _raw, document = read_json(path)
        if not isinstance(document, dict) or not document.get("id"):
            continue
        aliases = [alias for alias in (document.get("aliases") or []) if isinstance(alias, str)]
        cves = [alias for alias in aliases if CVE_RE.match(alias)]
        if CVE_RE.match(str(document.get("id"))):
            cves.append(document["id"])
        ghsas = [alias for alias in aliases if alias.startswith("GHSA-")]
        if str(document.get("id")).startswith("GHSA-"):
            ghsas.append(document["id"])
        ecosystems = set()
        for affected in document.get("affected") or []:
            ecosystem = eco_type((affected.get("package") or {}).get("ecosystem"))
            if ecosystem:
                ecosystems.add(ecosystem)
        ghsa_row = next((ghsa_rows[ghsa] for ghsa in ghsas if ghsa in ghsa_rows), None)
        records.append(
            {
                "id": document["id"],
                "services": services,
                "ecos": ecosystems,
                "cves": sorted(set(cves)),
                "ghsas": sorted(set(ghsas)),
                "kev": sorted(cve for cve in cves if cve in kev_ids),
                "nvd": sorted(cve for cve in cves if cve in nvd_cves),
                "ghsa_file": next((ghsa for ghsa in ghsas if ghsa in advisory_ids), None),
                "differ": ranges_differ(document, ghsa_row),
                "withdrawn": bool(document.get("withdrawn")),
                "batch": batch_of.get(document["id"]),
            }
        )
    return records, {index: batch for index, batch in enumerate(batches)}


def take(chosen: list[dict], seen: set[str], record: dict) -> None:
    if record["id"] in seen:
        return
    seen.add(record["id"])
    chosen.append(record)


def select(records: list[dict]) -> list[dict]:
    ordered = sorted(records, key=lambda record: record["id"])
    chosen: list[dict] = []
    seen: set[str] = set()
    for record in ordered:
        if record["withdrawn"] or record["kev"]:
            take(chosen, seen, record)
    ghsa_file_records = [record for record in ordered if record["ghsa_file"]]
    ghsa_file_records.sort(key=lambda record: (not record["differ"], not record["nvd"], record["id"]))
    for record in ghsa_file_records[:12]:
        take(chosen, seen, record)

    def count(predicate) -> int:
        return sum(1 for record in chosen if predicate(record))

    for record in ordered:
        if count(lambda item: str(item["id"]).startswith("PYSEC")) >= 5:
            break
        if str(record["id"]).startswith("PYSEC"):
            take(chosen, seen, record)
    for record in ordered:
        if count(lambda item: bool(item["nvd"])) >= 5:
            break
        if record["nvd"]:
            take(chosen, seen, record)
    for record in ordered:
        if count(lambda item: item["differ"]) >= 3:
            break
        if record["differ"]:
            take(chosen, seen, record)

    while len(chosen) < TARGET:
        service_counts: Counter[str] = Counter()
        eco_counts: Counter[str] = Counter()
        for record in chosen:
            service_counts.update(record["services"])
            eco_counts.update(record["ecos"])
        scarce_service_count = min(service_counts[service] for service in SERVICES)
        scarce_eco = "pypi" if eco_counts["pypi"] <= eco_counts["npm"] else "npm"
        best: dict | None = None
        best_key: tuple | None = None
        for record in ordered:
            if record["id"] in seen:
                continue
            adds_service = any(
                service in record["services"] and service_counts[service] == scarce_service_count
                for service in SERVICES
            )
            key = (
                0 if adds_service else 1,
                0 if scarce_eco in record["ecos"] else 1,
                0 if record["nvd"] else 1,
                0 if record["cves"] else 1,
                0 if record["differ"] else 1,
                record["id"],
            )
            if best_key is None or key < best_key:
                best_key = key
                best = record
        if best is None:
            break
        take(chosen, seen, best)
    return chosen


def quota_report(records: list[dict], chosen: list[dict]) -> list[str]:
    def has(items: list[dict], predicate) -> int:
        return sum(1 for item in items if predicate(item))

    lines = [
        f"Selected {len(chosen)} OSV vulnerability documents from {len(records)} on disk.",
        (
            "Withdrawn records on disk: "
            f"{has(records, lambda item: item['withdrawn'])}. "
            "None were present, so none are in the fixture."
        ),
        (
            "OSV records whose CVE alias is in the KEV catalogue: "
            f"{has(records, lambda item: item['kev'])} on disk, "
            f"{has(chosen, lambda item: item['kev'])} selected. "
            "The target was 3. Only the records that exist were copied."
        ),
        (
            f"PYSEC ids: {has(chosen, lambda item: str(item['id']).startswith('PYSEC'))} selected "
            f"(target 5, {has(records, lambda item: str(item['id']).startswith('PYSEC'))} on disk)."
        ),
        (
            f"Records with a GHSA per-advisory file: "
            f"{has(chosen, lambda item: item['ghsa_file'])} selected "
            f"(target 5, {has(records, lambda item: item['ghsa_file'])} on disk)."
        ),
        (
            f"Records with an NVD per-CVE file: "
            f"{has(chosen, lambda item: item['nvd'])} selected "
            f"(target 5, {has(records, lambda item: item['nvd'])} on disk)."
        ),
        (
            f"Records where the OSV and GHSA ranges differ: "
            f"{has(chosen, lambda item: item['differ'])} selected "
            f"(target 3, {has(records, lambda item: item['differ'])} on disk)."
        ),
    ]
    services = Counter(service for item in chosen for service in item["services"])
    ecosystems = Counter(eco for item in chosen for eco in item["ecos"])
    lines.append("Services: " + ", ".join(f"{name}={services[name]}" for name in SERVICES) + ".")
    lines.append("Ecosystems: " + ", ".join(f"{name}={ecosystems[name]}" for name in ("pypi", "npm")) + ".")
    lines.append("Ids: " + ", ".join(item["id"] for item in sorted(chosen, key=lambda item: item["id"])) + ".")
    available = {
        "pysec": has(records, lambda item: str(item["id"]).startswith("PYSEC")),
        "ghsa": has(records, lambda item: item["ghsa_file"]),
        "nvd": has(records, lambda item: item["nvd"]),
        "differ": has(records, lambda item: item["differ"]),
    }
    got = {
        "pysec": has(chosen, lambda item: str(item["id"]).startswith("PYSEC")),
        "ghsa": has(chosen, lambda item: item["ghsa_file"]),
        "nvd": has(chosen, lambda item: item["nvd"]),
        "differ": has(chosen, lambda item: item["differ"]),
    }
    targets = {"pysec": 5, "ghsa": 5, "nvd": 5, "differ": 3}
    for name, target in targets.items():
        if got[name] < min(target, available[name]):
            raise SystemExit(f"selection missed {name}: got {got[name]}, available {available[name]}")
    if any(services[name] == 0 for name in SERVICES) or ecosystems["pypi"] == 0 or ecosystems["npm"] == 0:
        raise SystemExit(f"selection missed a service or ecosystem: {services} {ecosystems}")
    return lines


class Catalog:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, relative: str, origin: str, fetched_at: str, raw: bytes, trim: str) -> None:
        self.rows.append(
            {
                "path": relative,
                "origin": origin,
                "fetched_at": fetched_at,
                "sha256": sha256(raw),
                "trim": trim,
                "bytes": len(raw),
            }
        )

    def write(self, path: Path, raw: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)


def copy_selected(chosen: list[dict], batches: dict[int, list[str]], catalog: Catalog) -> set[str]:
    for source in COPIED_SOURCES:
        destination = FIXTURE_DIR / source
        if destination.exists():
            shutil.rmtree(destination)
    cves: set[str] = set()
    for record in chosen:
        cves.update(record["cves"])
        source = SNAPSHOT_DIR / "osv" / f"vuln-{record['id']}.json"
        raw, _document = read_json(source)
        relative = f"osv/vuln-{record['id']}.json"
        catalog.write(FIXTURE_DIR / relative, raw)
        catalog.add(relative, "snapshot copy", file_stamp(source), raw, "none")

    batch_indexes = sorted({record["batch"] for record in chosen if record["batch"] is not None})
    for index in batch_indexes:
        name = f"querybatch-{index:03d}.json"
        source = SNAPSHOT_DIR / "osv" / name
        raw, _document = read_json(source)
        catalog.write(FIXTURE_DIR / "osv" / name, raw)
        catalog.add(f"osv/{name}", "snapshot copy", file_stamp(source), raw, "none")
        body = {"queries": [{"package": {"purl": purl}} for purl in batches[index]]}
        request_raw = (json.dumps(body, indent=2) + "\n").encode()
        request_name = f"querybatch-{index:03d}.request.json"
        catalog.write(FIXTURE_DIR / "osv" / request_name, request_raw)
        catalog.add(
            f"osv/{request_name}",
            "rebuilt request",
            stamp(),
            request_raw,
            "none. POST body rebuilt from the SBOM purls in sorted order, batches of 100, the same construction as fetch_osv. Not a server response.",
        )

    kev_name = "known_exploited_vulnerabilities.json"
    kev_path = SNAPSHOT_DIR / "kev" / kev_name
    kev_raw, _kev = read_json(kev_path)
    catalog.write(FIXTURE_DIR / "kev" / kev_name, kev_raw)
    catalog.add(f"kev/{kev_name}", "snapshot copy", file_stamp(kev_path), kev_raw, "none. Full catalogue.")

    epss_hits: set[str] = set()
    for path in sorted((SNAPSHOT_DIR / "epss").glob("batch-*.json")):
        raw, document = read_json(path)
        covered = {
            row.get("cve")
            for row in (document.get("data") or [])
            if isinstance(row, dict) and row.get("cve") in cves
        }
        if not covered:
            continue
        epss_hits.update(covered)
        catalog.write(FIXTURE_DIR / "epss" / path.name, raw)
        catalog.add(
            f"epss/{path.name}",
            "snapshot copy",
            file_stamp(path),
            raw,
            f"none. Whole batch file. Covers fixture CVEs: {', '.join(sorted(covered))}.",
        )
    missing_epss = sorted(cves - epss_hits)
    if missing_epss:
        print("note: fixture CVEs not in an EPSS batch: " + ", ".join(missing_epss))

    for cve in sorted(cves):
        path = SNAPSHOT_DIR / "nvd" / f"cve-{cve}.json"
        if not path.is_file():
            continue
        raw, _document = read_json(path)
        catalog.write(FIXTURE_DIR / "nvd" / path.name, raw)
        catalog.add(f"nvd/{path.name}", "snapshot copy", file_stamp(path), raw, "none")

    window_path = SNAPSHOT_DIR / "nvd" / "window-000.json"
    _raw, window = read_json(window_path)
    original = list(window.get("vulnerabilities") or [])
    fixture_rows = []
    others = []
    for item in original:
        cve_id = ((item.get("cve") or {}).get("id")) if isinstance(item, dict) else None
        if cve_id in cves:
            fixture_rows.append(item)
        else:
            others.append(item)
    trimmed = dict(window)
    trimmed["vulnerabilities"] = fixture_rows + others[:50]
    trimmed_raw = (json.dumps(trimmed, indent=2) + "\n").encode()
    catalog.write(FIXTURE_DIR / "nvd" / "window-000.json", trimmed_raw)
    catalog.add(
        "nvd/window-000.json",
        "snapshot copy, trimmed",
        file_stamp(window_path),
        trimmed_raw,
        (
            f"vulnerabilities reduced from {len(original)} to {len(trimmed['vulnerabilities'])}: "
            f"{len(fixture_rows)} fixture CVEs that appear on this page, plus the first 50 other CVEs in file order. "
            "Every other top-level field (resultsPerPage, startIndex, totalResults, format, version, timestamp) is unchanged."
        ),
    )

    copied_advisories: set[str] = set()
    for record in chosen:
        for ghsa in record["ghsas"]:
            path = SNAPSHOT_DIR / "ghsa" / f"advisory-{ghsa}.json"
            if not path.is_file() or ghsa in copied_advisories:
                continue
            copied_advisories.add(ghsa)
            raw, _document = read_json(path)
            catalog.write(FIXTURE_DIR / "ghsa" / path.name, raw)
            catalog.add(f"ghsa/{path.name}", "snapshot copy", file_stamp(path), raw, "none")
    for ecosystem in ("pip", "npm"):
        name = f"advisories-{ecosystem}-000.json"
        path = SNAPSHOT_DIR / "ghsa" / name
        raw, _document = read_json(path)
        catalog.write(FIXTURE_DIR / "ghsa" / name, raw)
        catalog.add(
            f"ghsa/{name}",
            "snapshot copy",
            file_stamp(path),
            raw,
            "none. First list page for this ecosystem. Later pages were not copied.",
        )
    return cves, missing_epss


def has_cisa_adp(document: object) -> bool:
    if not isinstance(document, dict):
        return False
    for adp in ((document.get("containers") or {}).get("adp") or []):
        short = str((adp.get("providerMetadata") or {}).get("shortName") or "")
        if "cisa" in short.lower():
            return True
    return False


def nvd_ssvc_hint(cves: set[str]) -> set[str]:
    hinted: set[str] = set()
    for cve in cves:
        path = SNAPSHOT_DIR / "nvd" / f"cve-{cve}.json"
        if not path.is_file():
            continue
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if "ssvc" in raw.lower() or "134c704f-9b21-4f2e-91b3-4a467353bcc0" in raw:
            hinted.add(cve)
    return hinted


class Fetcher:
    def __init__(self, email: str) -> None:
        self.email = email
        self.calls = 0
        self.client = httpx.Client(
            headers={"User-Agent": f"sibyl ({email})", "Accept": "application/json"},
            timeout=httpx.Timeout(30.0, read=60.0),
            follow_redirects=True,
        )

    def close(self) -> None:
        self.client.close()

    def redact(self, text: str) -> str:
        if self.email:
            return text.replace(self.email, "<email>")
        return text

    def get(self, url: str) -> httpx.Response | None:
        if self.calls >= MAX_GETS:
            print(self.redact(f"stop: 12 GET budget spent before {url}"))
            return None
        if self.calls:
            time.sleep(0.4)
        self.calls += 1
        print(f"GET {self.calls}/{MAX_GETS} {url}")
        try:
            return self.client.get(url)
        except httpx.HTTPError as exc:
            print(f"  failed: {exc.__class__.__name__}")
            return None


def paging_notes(response: httpx.Response, payload: object) -> list[str]:
    notes = [f"HTTP {response.status_code}", f"final url: {response.url}"]
    for header in ("link", "x-total-count", "x-total-pages", "x-page", "x-next-page"):
        value = response.headers.get(header)
        if value:
            notes.append(f"header {header}: {value[:300]}")
    if isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(value, list):
                notes.append(f"json {key}: list length {len(value)}")
            elif not isinstance(value, dict):
                notes.append(f"json {key}: {value}")
        notes.append("json object keys: " + ", ".join(payload.keys()))
    elif isinstance(payload, list):
        notes.append(f"json list length {len(payload)}")
        if payload and isinstance(payload[0], dict):
            notes.append("json item keys: " + ", ".join(payload[0].keys()))
    return notes


def fetch_missing(cves: set[str], kev_cves: set[str], catalog: Catalog, email: str) -> list[str]:
    notes: list[str] = []
    fetcher = Fetcher(email)
    try:
        response = fetcher.get(EUVD_EXPLOITED_URL)
        if response is None:
            notes.append("EUVD exploited list was not fetched.")
        else:
            body = response.content
            if email and email.encode() in body:
                raise SystemExit("EUVD body echoed the contact email; not saved")
            try:
                payload = response.json()
            except json.JSONDecodeError:
                payload = None
            relative = "euvd/exploitedvulnerabilities.json"
            catalog.write(FIXTURE_DIR / relative, body)
            detail = " ".join(paging_notes(response, payload))
            catalog.add(relative, "--fetch-missing", stamp(), body, f"none. {detail}")
            notes.append("EUVD exploited list paging: " + detail)
        hinted = nvd_ssvc_hint(cves)
        candidates = sorted(cves, key=lambda cve: (cve not in kev_cves, cve not in hinted, cve))
        saved: list[tuple[str, bytes, bool]] = []
        for cve in candidates:
            if len(saved) >= 5 and any(item[2] for item in saved):
                break
            if len(saved) >= 5 and fetcher.calls >= MAX_GETS - 5:
                break
            if any(item[0] == cve for item in saved):
                continue
            # Keep one spare GET per remaining EUVD id, plus the calls still needed.
            remaining_euvd = 5
            if fetcher.calls + remaining_euvd >= MAX_GETS and len(saved) >= 5:
                break
            response = fetcher.get(CVE_URL.format(id=cve))
            if response is None or response.status_code != 200:
                status = response.status_code if response is not None else "no response"
                notes.append(f"CVE.org {cve} not saved (HTTP {status}).")
                continue
            if email and email.encode() in response.content:
                raise SystemExit(f"CVE.org body for {cve} echoed the contact email; not saved")
            try:
                document = response.json()
            except json.JSONDecodeError:
                notes.append(f"CVE.org {cve} was not JSON.")
                continue
            saved.append((cve, response.content, has_cisa_adp(document)))
            if len(saved) > 5:
                drop_at = next(
                    (
                        index
                        for index, item in enumerate(saved)
                        if item[0] not in kev_cves and not item[2]
                    ),
                    None,
                )
                if drop_at is not None and has_cisa_adp(document):
                    dropped = saved.pop(drop_at)
                    notes.append(f"Replaced {dropped[0]} with {cve} because {cve} has a CISA-ADP container.")
                elif len(saved) > 5:
                    saved.pop()
        if not saved:
            notes.append("No CVE.org records were saved.")
        if not any(item[2] for item in saved):
            notes.append("None of the saved CVE.org records contained a CISA-ADP container.")
        final_ids = [item[0] for item in saved[:5]]
        for cve, body, adp in saved[:5]:
            relative = f"cve/{cve}.json"
            catalog.write(FIXTURE_DIR / relative, body)
            catalog.add(
                relative,
                "--fetch-missing",
                stamp(),
                body,
                "none" + (". Contains a CISA-ADP container." if adp else "."),
            )
        for cve in final_ids:
            response = fetcher.get(f"{EUVD_ID_URL}?id={cve}")
            if response is None:
                notes.append(f"EUVD {cve} was not fetched.")
                continue
            if email and email.encode() in response.content:
                raise SystemExit(f"EUVD body for {cve} echoed the contact email; not saved")
            relative = f"euvd/{cve}.json"
            catalog.write(FIXTURE_DIR / relative, response.content)
            catalog.add(
                relative,
                "--fetch-missing",
                stamp(),
                response.content,
                f"none. HTTP {response.status_code}. This is the fetch_euvd per-id call.",
            )
        notes.append(f"GET calls used: {fetcher.calls} of {MAX_GETS}.")
        notes.append("CVE.org ids saved: " + (", ".join(final_ids) if final_ids else "none") + ".")
        if any(cve in kev_cves for cve in final_ids):
            notes.append("At least one saved CVE.org id is in the KEV catalogue.")
        else:
            notes.append("No saved CVE.org id is in the KEV catalogue.")
    finally:
        fetcher.close()
    return notes


def write_doc(catalog: Catalog, selection: list[str], fetch_notes: list[str]) -> None:
    total = sum(row["bytes"] for row in catalog.rows)
    lines = [
        "# Frozen fixtures",
        "",
        "These files are real API responses (or, for `*.request.json` only, the POST body rebuilt from the SBOM purls). "
        "Part E re-runs ingestion, the Zetaris check, the matcher, and the baselines on the full snapshots. "
        "This directory stays the offline test set and is not replaced by those snapshots.",
        "",
        "Regenerate the copied subset with `uv run scripts/freeze_fixtures.py`. "
        "That reads `data/sample/snapshots/` and rewrites `osv/`, `ghsa/`, `kev/`, `epss/`, and `nvd/`. "
        "`uv run scripts/freeze_fixtures.py --fetch-missing` also does at most 12 GETs "
        "(`User-Agent: sibyl (<CONTACT_EMAIL>)`) for CVE.org and EUVD, and skips that work only when you leave the existing `cve/` and `euvd/` files in place. "
        "Delete those two directories first if you want them fetched again. "
        "The contact email is not written into these files.",
        "",
        "Fetch dates on snapshot copies are the local file modification time in UTC, which is when the snapshot script wrote the file. "
        "The snapshot manifest does not store a fetch timestamp for these objects.",
        "",
        "Synthetic 429 and 5xx responses are not files. Tests build them with `httpx.MockTransport`. "
        "A malformed body and an empty body live in `tests/fixtures/synthetic/` and are marked synthetic in the file itself. "
        "The prompt-injection advisory is P5 and is not here.",
        "",
        "EUVD `GET /api/exploitedvulnerabilities` does not page. ENISA documents it as the latest exploited "
        "vulnerabilities, maximum 8 records. `page` and `size` are ignored. `/api/search` is the paged catalogue "
        "(`page` from 0, `size` max 100).",
        "",
        "## Selection",
        "",
    ]
    lines.extend(f"- {line}" for line in selection)
    if fetch_notes:
        lines.extend(["", "## CVE.org and EUVD", ""])
        lines.extend(f"- {line}" for line in fetch_notes)
    lines.extend(
        [
            "",
            f"## Files ({len(catalog.rows)}, {total} bytes)",
            "",
            "| File | Origin | Fetched | SHA256 | Trim |",
            "|---|---|---|---|---|",
        ]
    )
    for row in sorted(catalog.rows, key=lambda item: item["path"]):
        trim = row["trim"].replace("|", "/")
        lines.append(
            f"| `{row['path']}` | {row['origin']} | {row['fetched_at']} | `{row['sha256']}` | {trim} |"
        )
    lines.append("")
    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOC_PATH.write_text("\n".join(lines), encoding="utf-8")


def fetched_already() -> bool:
    return (FIXTURE_DIR / "euvd" / "exploitedvulnerabilities.json").is_file() and (
        len(list((FIXTURE_DIR / "cve").glob("CVE-*.json"))) >= 5
    )


def catalog_existing_fetches(catalog: Catalog) -> None:
    """Hash CVE.org and EUVD files already on disk. Does not fetch."""
    for directory, label in (("cve", "cve"), ("euvd", "euvd")):
        folder = FIXTURE_DIR / directory
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("*.json")):
            raw = path.read_bytes()
            trim = "none."
            if directory == "cve":
                try:
                    if has_cisa_adp(json.loads(raw)):
                        trim = "none. Contains a CISA-ADP container."
                except json.JSONDecodeError:
                    trim = "none. Body is not JSON."
            elif path.name != "exploitedvulnerabilities.json":
                trim = "none. This is the fetch_euvd per-id call."
            else:
                trim = "none. Latest exploited list. The endpoint does not page."
            catalog.add(f"{label}/{path.name}", "--fetch-missing", file_stamp(path), raw, trim)


def directory_size(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def _recent(path: Path, seconds: float = 120) -> bool:
    return (datetime.now(timezone.utc).timestamp() - path.stat().st_mtime) < seconds


def _error_body(raw: bytes) -> bool:
    stripped = raw.strip()
    if not stripped or stripped[:1] not in {b"{", b"["}:
        return False
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return False
    return isinstance(payload, dict) and isinstance(payload.get("error"), str) and "id" not in payload


def _osv_for_cve(cve: str) -> list[str]:
    found: list[str] = []
    for path in sorted((SNAPSHOT_DIR / "osv").glob("vuln-*.json")):
        if _recent(path):
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        aliases = document.get("aliases") or []
        if document.get("id") == cve or cve in aliases:
            identifier = str(document.get("id") or "")
            if identifier:
                found.append(identifier)
    return found


def _epss_batch_for(cve: str) -> Path | None:
    for path in sorted((SNAPSHOT_DIR / "epss").glob("batch-*.json")):
        if _recent(path):
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for row in document.get("data") or []:
            if isinstance(row, dict) and row.get("cve") == cve:
                return path
    return None


def related_snapshot_files(identifier: str) -> list[tuple[Path, str]]:
    """Per-id snapshot files for one OSV id or CVE id. Does not include list pages."""
    pairs: list[tuple[Path, str]] = []
    seen: set[str] = set()

    def add(src: Path, relative: str) -> None:
        if relative in seen or not src.is_file() or _recent(src):
            return
        seen.add(relative)
        pairs.append((src, relative))

    osv_ids = [identifier]
    cves: list[str] = []
    if identifier.startswith("CVE-"):
        cves.append(identifier)
        osv_ids = _osv_for_cve(identifier)
    for osv_id in osv_ids:
        add(SNAPSHOT_DIR / "osv" / f"vuln-{osv_id}.json", f"osv/vuln-{osv_id}.json")
        path = SNAPSHOT_DIR / "osv" / f"vuln-{osv_id}.json"
        if not path.is_file() or _recent(path):
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        aliases = [osv_id]
        aliases.extend(alias for alias in (document.get("aliases") or []) if isinstance(alias, str))
        for alias in aliases:
            if alias.startswith("GHSA-"):
                add(SNAPSHOT_DIR / "ghsa" / f"advisory-{alias}.json", f"ghsa/advisory-{alias}.json")
            if CVE_RE.match(alias):
                cves.append(alias)
    for cve in dict.fromkeys(cves):
        add(SNAPSHOT_DIR / "nvd" / f"cve-{cve}.json", f"nvd/cve-{cve}.json")
        add(SNAPSHOT_DIR / "cve" / f"{cve}.json", f"cve/{cve}.json")
        add(SNAPSHOT_DIR / "euvd" / f"{cve}.json", f"euvd/{cve}.json")
        batch = _epss_batch_for(cve)
        if batch is not None:
            add(batch, f"epss/{batch.name}")
    return pairs


def append_fixture_rows(copied: list[tuple[str, str]]) -> None:
    """Insert table rows for files --add copied. Leave every existing row alone."""
    if not copied:
        return
    text = DOC_PATH.read_text(encoding="utf-8")
    present = {line.split("`", 2)[1] for line in text.splitlines() if line.startswith("| `")}
    new_lines = []
    for relative, trim in copied:
        if relative in present:
            continue
        path = FIXTURE_DIR / relative
        raw = path.read_bytes()
        new_lines.append(
            f"| `{relative}` | snapshot copy | {file_stamp(path)} | `{sha256(raw)}` | {trim.replace('|', '/')} |"
        )
    if not new_lines:
        return
    lines = text.splitlines()
    table: list[str] = []
    out: list[str] = []
    in_table = False
    flushed = False
    for line in lines:
        if line.startswith("| `"):
            in_table = True
            table.append(line)
            continue
        if in_table:
            def sort_key(row: str) -> str:
                return row.split("`", 2)[1]

            out.extend(sorted(table + new_lines, key=sort_key))
            in_table = False
            flushed = True
            table = []
        out.append(line)
    if table and not flushed:
        def sort_key(row: str) -> str:
            return row.split("`", 2)[1]

        out.extend(sorted(table + new_lines, key=sort_key))
    body = "\n".join(out) + "\n"
    listed = [line.split("`", 2)[1] for line in body.splitlines() if line.startswith("| `")]
    total = sum((FIXTURE_DIR / relative).stat().st_size for relative in listed)
    body, count = re.subn(
        r"## Files \(\d+, \d+ bytes\)",
        f"## Files ({len(listed)}, {total} bytes)",
        body,
        count=1,
    )
    if count != 1:
        raise SystemExit("FIXTURES.md has no file-count heading")
    DOC_PATH.write_text(body, encoding="utf-8")


def add_ids(identifiers: list[str]) -> int:
    """Copy records and their per-id files. Do not rewrite fixtures that are already there."""
    if not SNAPSHOT_DIR.is_dir():
        print("FAIL freeze: no snapshot directory", file=sys.stderr)
        return 1
    copied: list[tuple[str, str]] = []
    trim = "none. Copied by --add. Files already in the fixture were left unchanged."
    for identifier in identifiers:
        pairs = related_snapshot_files(identifier)
        if not pairs:
            print(f"none on disk for {identifier}")
            continue
        for src, relative in pairs:
            dest = FIXTURE_DIR / relative
            if dest.exists():
                print(f"keep {relative}")
                continue
            raw = src.read_bytes()
            if relative.startswith("euvd/") and _error_body(raw):
                print(f"skip {relative}: EUVD error body")
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            os.utime(dest, ns=(src.stat().st_atime_ns, src.stat().st_mtime_ns))
            copied.append((relative, trim))
            print(f"added {relative}")
    append_fixture_rows(copied)
    total = directory_size(FIXTURE_DIR)
    print(f"added {len(copied)} file(s); fixture bytes={total}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Freeze a snapshot subset into tests/fixtures.")
    parser.add_argument(
        "--fetch-missing",
        action="store_true",
        help="GET up to 12 CVE.org and EUVD responses that are not in the snapshot yet",
    )
    parser.add_argument(
        "--add",
        nargs="+",
        metavar="ID",
        help="Copy these OSV ids or CVE ids and their per-id files without rewriting existing fixtures",
    )
    args = parser.parse_args(argv)
    if args.add:
        return add_ids(args.add)
    if not SNAPSHOT_DIR.is_dir():
        print("FAIL freeze: no snapshot directory", file=sys.stderr)
        return 1
    purl_services = load_purls()
    records, batches = load_records(SNAPSHOT_DIR, purl_services)
    chosen = select(records)
    selection = quota_report(records, chosen)
    for line in selection:
        print(line)
    catalog = Catalog()
    cves, missing_epss = copy_selected(chosen, batches, catalog)
    if missing_epss:
        selection.append(
            "EPSS: fixture CVEs not in any batch on disk: " + ", ".join(missing_epss) + "."
        )
    kev_cves = {cve for record in chosen for cve in record["kev"]}
    fetch_notes: list[str] = []
    if args.fetch_missing and fetched_already():
        catalog_existing_fetches(catalog)
        fetch_notes.append(
            "cve/ and euvd/ already exist, so --fetch-missing did not call the network. "
            "Delete those directories to fetch them again."
        )
    elif args.fetch_missing:
        email = load_env(ENV_PATH).get("CONTACT_EMAIL", "").strip()
        if not email:
            print("FAIL freeze: CONTACT_EMAIL is empty", file=sys.stderr)
            return 1
        fetch_notes = fetch_missing(cves, kev_cves, catalog, email)
        for line in fetch_notes:
            print(line)
    elif (FIXTURE_DIR / "cve").is_dir() or (FIXTURE_DIR / "euvd").is_dir():
        catalog_existing_fetches(catalog)
        fetch_notes.append(
            "cve/ and euvd/ were left in place from the earlier --fetch-missing run."
        )
    write_doc(catalog, selection, fetch_notes)
    total = directory_size(FIXTURE_DIR)
    print(f"fixture bytes={total} files={sum(1 for _ in FIXTURE_DIR.rglob('*') if _.is_file())}")
    if total > SIZE_LIMIT:
        print(f"FAIL freeze: fixtures are {total} bytes, limit is {SIZE_LIMIT}", file=sys.stderr)
        return 1
    print(f"wrote {DOC_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
