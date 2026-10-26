"""Find services and their components in a checkout.

`cdxgen -r` writes one CycloneDX SBOM for the whole tree. Every component
carries the manifest it came from (`SrcFile`), so a service is a directory
that holds its own manifest. A directory whose path has a test, example or
docs segment is skipped and listed in `skipped`.

Without `mvn`, Maven gives direct dependencies only; Go needs `go.sum` for
the full set. Both are noted in `limits` when they apply.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from sibyl.config import Settings
from sibyl.inventory.purls import Component, covered, parse

MANIFESTS = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "requirements.in",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "uv.lock",
    "setup.py",
    "setup.cfg",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "go.mod",
    "go.sum",
}
SKIP_SEGMENTS = {
    "test",
    "tests",
    "__tests__",
    "testdata",
    "fixtures",
    "examples",
    "example",
    "samples",
    "sample",
    "docs",
    "doc",
    "node_modules",
    "vendor",
    "third_party",
    ".git",
}
EXCLUDES = ["**/node_modules/**", "**/.git/**", "**/vendor/**", "**/dist/**", "**/build/**"]
SCAN_TIMEOUT = 1800


class ScanError(RuntimeError):
    pass


@dataclass
class FoundComponent:
    component: Component
    direct: bool
    source_file: str


@dataclass
class Candidate:
    path: str  # "" for the repository root
    name: str
    manifests: list[str] = field(default_factory=list)
    components: list[FoundComponent] = field(default_factory=list)

    @property
    def ecosystems(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for item in self.components:
            counts[item.component.ecosystem] += 1
        return dict(counts)


@dataclass
class ScanResult:
    candidates: list[Candidate]
    skipped: list[str] = field(default_factory=list)
    not_covered: dict[str, int] = field(default_factory=dict)
    limits: list[str] = field(default_factory=list)


def is_manifest(path: str) -> bool:
    return PurePosixPath(path).name in MANIFESTS


def skipped_path(path: str) -> bool:
    return any(part.lower() in SKIP_SEGMENTS for part in PurePosixPath(path).parts)


def service_dir(path: str) -> str:
    parent = str(PurePosixPath(path).parent)
    return "" if parent == "." else parent


def run_cdxgen(target: Path, settings: Settings, *, recurse: bool = True) -> dict:
    """The CycloneDX document cdxgen writes for `target`."""
    with tempfile.TemporaryDirectory(prefix="sibyl-scan-") as scratch:
        out = Path(scratch) / "bom.json"
        command = shlex.split(settings.cdxgen_cmd) + [
            "--no-install-deps",
            "--no-babel",
            "--spec-version",
            "1.6",
            "-o",
            str(out),
        ]
        if recurse:
            command.append("-r")
        else:
            command.append("--no-recurse")
        for pattern in EXCLUDES:
            command.extend(["--exclude", pattern])
        command.append(str(target))
        env = os.environ.copy()
        env["FETCH_LICENSE"] = "false"
        try:
            done = subprocess.run(command, cwd=scratch, env=env, capture_output=True, text=True, timeout=SCAN_TIMEOUT, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ScanError("cdxgen timed out") from exc
        except FileNotFoundError as exc:
            raise ScanError(f"cannot run {command[0]}") from exc
        if not out.is_file():
            detail = " ".join((done.stderr or done.stdout or "").split())[-400:]
            raise ScanError(f"cdxgen wrote no SBOM (exit {done.returncode}): {detail}")
        try:
            return json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ScanError("cdxgen output was not JSON") from exc


def candidates_from(document: dict, root: Path, *, only: set[str] | None = None) -> ScanResult:
    """Group the SBOM's components by the directory of their manifest.

    `only` keeps just those directories (an incremental scan of named services).
    """
    directs = _direct_refs(document)
    by_dir: dict[str, Candidate] = {}
    skipped: set[str] = set()
    not_covered: dict[str, int] = defaultdict(int)
    seen: set[tuple[str, str]] = set()
    root_text = str(root.resolve())
    for raw in _flatten(document.get("components")):
        purl = raw.get("purl") or ""
        component = parse(purl, raw.get("name") or "", raw.get("version") or "")
        if component is None:
            continue
        source = _relative(_source_file(raw), root_text)
        directory = service_dir(source) if source else ""
        if source and skipped_path(source):
            skipped.add(directory)
            continue
        if only is not None and directory not in only:
            continue
        if not covered(component.ecosystem):
            not_covered[component.ecosystem] += 1
        if (directory, purl) in seen:
            continue
        seen.add((directory, purl))
        candidate = by_dir.get(directory)
        if candidate is None:
            name = PurePosixPath(directory).name if directory else root.name
            candidate = by_dir[directory] = Candidate(path=directory, name=name)
        if source and source not in candidate.manifests:
            candidate.manifests.append(source)
        ref = raw.get("bom-ref") or ""
        candidate.components.append(FoundComponent(component, ref in directs or purl in directs, source))
    limits = _limits(by_dir.values(), root)
    return ScanResult(
        candidates=sorted(by_dir.values(), key=lambda item: item.path),
        skipped=sorted(skipped),
        not_covered=dict(not_covered),
        limits=limits,
    )


def scan(root: Path, settings: Settings, *, only: set[str] | None = None) -> ScanResult:
    """Scan the whole tree, or only the named service directories."""
    if only is None:
        return candidates_from(run_cdxgen(root, settings), root)
    results: list[ScanResult] = []
    for directory in sorted(only):
        target = root / directory if directory else root
        if not target.is_dir():
            continue
        document = run_cdxgen(target, settings)
        results.append(candidates_from(document, root, only={directory}))
    merged = ScanResult(candidates=[])
    for result in results:
        merged.candidates.extend(result.candidates)
        merged.skipped.extend(result.skipped)
        merged.limits.extend(item for item in result.limits if item not in merged.limits)
        for key, value in result.not_covered.items():
            merged.not_covered[key] = merged.not_covered.get(key, 0) + value
    return merged


def _limits(candidates, root: Path) -> list[str]:
    notes: list[str] = []
    for candidate in candidates:
        names = {PurePosixPath(path).name for path in candidate.manifests}
        base = root / candidate.path if candidate.path else root
        label = candidate.path or "(root)"
        if "pom.xml" in names and not _has_tool("mvn"):
            notes.append(f"{label}: Maven direct dependencies only (mvn is not installed)")
        if "go.mod" in names and not (base / "go.sum").is_file():
            notes.append(f"{label}: Go direct dependencies only (no go.sum)")
    return notes


def _has_tool(name: str) -> bool:
    from shutil import which

    return which(name) is not None


def _source_file(component: dict) -> str:
    for prop in component.get("properties") or []:
        if prop.get("name") == "SrcFile" and prop.get("value"):
            return str(prop["value"])
    for occurrence in (component.get("evidence") or {}).get("occurrences") or []:
        if occurrence.get("location"):
            return str(occurrence["location"])
    return ""


def _relative(path: str, root: str) -> str:
    if not path:
        return ""
    if path.startswith(root):
        path = path[len(root):]
    return path.lstrip("/")


def _flatten(components: list | None) -> list[dict]:
    found: list[dict] = []
    for component in components or []:
        if isinstance(component, dict):
            found.append(component)
            found.extend(_flatten(component.get("components")))
    return found


def _direct_refs(document: dict) -> set[str]:
    """Components the project roots depend on directly (one level below each root)."""
    roots = {((document.get("metadata") or {}).get("component") or {}).get("bom-ref")}
    for entry in document.get("dependencies") or []:
        ref = entry.get("ref") or ""
        if not ref.startswith("pkg:"):
            roots.add(ref)
    direct: set[str] = set()
    for entry in document.get("dependencies") or []:
        if entry.get("ref") in roots:
            direct.update(entry.get("dependsOn") or [])
    return direct
