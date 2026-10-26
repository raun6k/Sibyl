#!/usr/bin/env python3
"""Check the sample CycloneDX SBOMs.

Passes only when every component has a purl and the total count is in range.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SBOM_DIR = ROOT / "data" / "sample" / "sboms"
EXPECTED = (
    "checkout-api.cdx.json",
    "internal-admin.cdx.json",
    "merchant-portal.cdx.json",
    "reporting-worker.cdx.json",
)
MIN_TOTAL = 250
MAX_TOTAL = 450


def flatten(components: list | None) -> list[dict]:
    found: list[dict] = []
    for component in components or []:
        found.append(component)
        found.extend(flatten(component.get("components")))
    return found


def ecosystem(purl: str) -> str:
    if not purl.startswith("pkg:"):
        return "unknown"
    return purl[4:].split("/", 1)[0] or "unknown"


def direct_refs(document: dict) -> set[str]:
    metadata = document.get("metadata") or {}
    root = metadata.get("component") or {}
    root_ref = root.get("bom-ref")
    depends: set[str] = set()
    for entry in document.get("dependencies") or []:
        if root_ref and entry.get("ref") == root_ref:
            depends.update(entry.get("dependsOn") or [])
    return depends


def main() -> int:
    files = [SBOM_DIR / name for name in EXPECTED]
    missing = [path.name for path in files if not path.is_file()]
    if missing:
        print(f"missing SBOM files: {', '.join(missing)}", file=sys.stderr)
        return 1

    total = 0
    missing_purls = 0
    for path in files:
        document = json.loads(path.read_text())
        components = flatten(document.get("components"))
        purls = [component.get("purl") or "" for component in components]
        ecosystems = Counter(ecosystem(purl) if purl else "missing" for purl in purls)
        directs = direct_refs(document)
        direct_count = sum(
            1
            for component in components
            if component.get("bom-ref") in directs or (component.get("purl") or "") in directs
        )
        with_purl = sum(1 for purl in purls if purl)
        missing_here = len(components) - with_purl
        missing_purls += missing_here
        total += len(components)
        eco = ", ".join(f"{name}={count}" for name, count in sorted(ecosystems.items()))
        print(
            f"{path.name}: components={len(components)} "
            f"with_purl={with_purl} direct={direct_count} ecosystems={eco}"
        )
        if missing_here:
            print(f"  missing purl on {missing_here} component(s)", file=sys.stderr)

    print(f"total={total} required={MIN_TOTAL}..{MAX_TOTAL}")
    in_range = MIN_TOTAL <= total <= MAX_TOTAL
    if missing_purls or not in_range:
        print("FAIL")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
