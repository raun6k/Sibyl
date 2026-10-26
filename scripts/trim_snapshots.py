#!/usr/bin/env python3
"""Write a sample subset of the full snapshots.

The full download stays in data/sample/snapshots. This script reads it and
writes data/sample/snapshot-subset. Re-running replaces that directory.

Kept byte for byte: KEV, EPSS, OSV, GHSA, CVE.org, and NVD per-CVE files.
NVD window pages drop vulnerabilities whose CPE product matches no sample
package and whose CVE id is not already in OSV, GHSA, or CVE.org. EUVD
files keep only the fields the collector reads.

    uv run scripts/trim_snapshots.py
    uv run scripts/trim_snapshots.py --source data/sample/snapshots --dest data/sample/snapshot-subset
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from seed_db import load_sample  # noqa: E402
from sibyl.tools.collectors.nvd import _cpe_rows  # noqa: E402

DEFAULT_SOURCE = ROOT / "data" / "sample" / "snapshots"
DEFAULT_DEST = ROOT / "data" / "sample" / "snapshot-subset"
COPY_SOURCES = ("osv", "ghsa", "kev", "epss", "cve")
EUVD_FIELDS = (
    "id",
    "aliases",
    "baseScore",
    "baseScoreVector",
    "baseScoreVersion",
    "error",
    "message",
)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sample_names() -> set[str]:
    _services, _sboms, components = load_sample()
    return {name.lower() for _component_id, _sbom, _purl, _ecosystem, name, _version, _direct in components}


def linked_cve_ids(source: Path) -> set[str]:
    """CVE ids named by the sources this subset keeps in full."""
    found: set[str] = set()
    for path in (source / "cve").glob("CVE-*.json"):
        found.add(path.stem)
    for path in (source / "nvd").glob("cve-CVE-*.json"):
        found.add(path.name.removeprefix("cve-").removesuffix(".json"))
    for path in (source / "osv").glob("*.json"):
        _collect_ids(path, found)
    for path in (source / "ghsa").glob("advisory-*.json"):
        _collect_ids(path, found)
    return {cve for cve in found if cve.startswith("CVE-")}


def _collect_ids(path: Path, found: set[str]) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    rows = payload if isinstance(payload, list) else [payload]
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in ("id", "cve_id"):
            value = row.get(key)
            if isinstance(value, str) and value.startswith("CVE-"):
                found.add(value)
        aliases = row.get("aliases")
        if isinstance(aliases, list):
            for alias in aliases:
                if isinstance(alias, str) and alias.startswith("CVE-"):
                    found.add(alias)
        for vuln in row.get("vulnerabilities") or []:
            if isinstance(vuln, dict):
                cve = vuln.get("cve_id") or ((vuln.get("cve") or {}).get("id") if isinstance(vuln.get("cve"), dict) else None)
                if isinstance(cve, str) and cve.startswith("CVE-"):
                    found.add(cve)


def cpe_matches(item: dict, names: set[str]) -> bool:
    cve = item.get("cve") if isinstance(item.get("cve"), dict) else {}
    cve_id = str(cve.get("id") or "")
    for row in _cpe_rows(cve, cve_id):
        if row.package.lower() in names:
            return True
    return False


def trim_window(payload: dict, names: set[str], linked: set[str]) -> tuple[dict, str]:
    original = list(payload.get("vulnerabilities") or [])
    kept = []
    matched = linked_kept = 0
    for item in original:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve") if isinstance(item.get("cve"), dict) else {}
        cve_id = cve.get("id") if isinstance(cve.get("id"), str) else ""
        by_product = cpe_matches(item, names)
        by_link = cve_id in linked
        if not by_product and not by_link:
            continue
        kept.append(item)
        matched += int(by_product)
        linked_kept += int(by_link and not by_product)
    trimmed = dict(payload)
    trimmed["vulnerabilities"] = kept
    note = (
        f"vulnerabilities {len(original)} -> {len(kept)} "
        f"({matched} CPE product matches a sample package, {linked_kept} kept because the CVE id is in OSV, GHSA, or CVE.org). "
        "Other top-level fields are unchanged. Dropped entries cannot reach a sample component."
    )
    return trimmed, note


def trim_euvd(payload: object) -> tuple[object, str]:
    if isinstance(payload, list):
        return [_trim_euvd_object(item) if isinstance(item, dict) else item for item in payload], (
            "each object keeps id, aliases, baseScore, baseScoreVector, baseScoreVersion, error, message"
        )
    if isinstance(payload, dict):
        return _trim_euvd_object(payload), (
            "kept id, aliases, baseScore, baseScoreVector, baseScoreVersion, error, message; "
            "dropped every other field, including enisaIdAdvisory and references"
        )
    return payload, "unchanged; not a JSON object"


def _trim_euvd_object(item: dict) -> dict:
    if "error" in item and "id" not in item:
        return {key: item[key] for key in ("error", "message") if key in item}
    return {key: item[key] for key in EUVD_FIELDS if key in item}


def read_json(path: Path) -> object:
    raw = path.read_bytes()
    if path.name.endswith(".gz"):
        raw = gzip.decompress(raw)
    return json.loads(raw)


def write_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def copy_tree(source: Path, dest: Path, relative: str, files: list[dict]) -> None:
    origin = source / relative
    if not origin.is_dir():
        raise SystemExit(f"missing {origin}")
    for path in sorted(item for item in origin.rglob("*") if item.is_file()):
        raw = path.read_bytes()
        rel = f"{relative}/{path.relative_to(origin).as_posix()}"
        write_bytes(dest / rel, raw)
        files.append({"path": rel, "sha256": sha256(raw), "bytes": len(raw), "trimmed": "none"})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the sample snapshot subset.")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    args = parser.parse_args(argv)
    source = args.source.resolve()
    dest = args.dest.resolve()
    if not source.is_dir():
        print(f"FAIL trim: {source} is not a directory", file=sys.stderr)
        return 1
    if dest == source or source in dest.parents:
        print("FAIL trim: dest must be a different directory from source", file=sys.stderr)
        return 1
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    names = sample_names()
    linked = linked_cve_ids(source)
    files: list[dict] = []
    for relative in COPY_SOURCES:
        copy_tree(source, dest, relative, files)
    nvd = source / "nvd"
    for path in sorted(nvd.glob("cve-*.json")):
        raw = path.read_bytes()
        rel = f"nvd/{path.name}"
        write_bytes(dest / rel, raw)
        files.append({"path": rel, "sha256": sha256(raw), "bytes": len(raw), "trimmed": "none"})
    windows = sorted(path for path in nvd.glob("window-*.json*") if ".json" in path.name)
    for path in windows:
        payload = read_json(path)
        trimmed, note = trim_window(payload, names, linked)
        raw = (json.dumps(trimmed, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        name = path.name[:-3] if path.name.endswith(".gz") else path.name
        rel = f"nvd/{name}"
        write_bytes(dest / rel, raw)
        files.append({"path": rel, "sha256": sha256(raw), "bytes": len(raw), "trimmed": note})
        print(f"{rel}: {note}")
    euvd = source / "euvd"
    for path in sorted(item for item in euvd.glob("*.json") if item.is_file()):
        payload = json.loads(path.read_text(encoding="utf-8"))
        trimmed, note = trim_euvd(payload)
        raw = (json.dumps(trimmed, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        rel = f"euvd/{path.name}"
        write_bytes(dest / rel, raw)
        files.append({"path": rel, "sha256": sha256(raw), "bytes": len(raw), "trimmed": note})
    window = {}
    manifest_path = source / "manifest.json"
    if manifest_path.is_file():
        window = json.loads(manifest_path.read_text(encoding="utf-8")).get("window") or {}
    total = sum(item["bytes"] for item in files)
    document = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": str(source.relative_to(ROOT)) if source.is_relative_to(ROOT) else str(source),
        "window": window,
        "trim_rule": (
            "Keep KEV, EPSS, OSV, GHSA, and CVE.org byte for byte. Keep NVD per-CVE files byte for byte. "
            "On NVD window pages, keep a vulnerability when a CPE product name matches a sample package "
            "(the same package string B1 joins on) or when its CVE id is already in OSV, GHSA, or CVE.org. "
            "On EUVD files, keep only the fields the collector reads."
        ),
        "bytes": total,
        "files": files,
    }
    raw = (json.dumps(document, indent=2) + "\n").encode()
    write_bytes(dest / "manifest.json", raw)
    print(f"wrote {dest.relative_to(ROOT)} files={len(files)} bytes={total + len(raw)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
