"""Shared normalisation: names, alias pairs, canonical hashes, CVSS 3.x scores."""

from __future__ import annotations

import hashlib
import json
import math
import re

_ECOSYSTEMS = {
    "pypi": "pypi",
    "PyPI": "pypi",
    "pip": "pypi",
    "PIP": "pypi",
    "npm": "npm",
    "NPM": "npm",
    "Maven": "maven",
    "maven": "maven",
    "MAVEN": "maven",
    "Go": "golang",
    "go": "golang",
    "GO": "golang",
    "golang": "golang",
}

# CVSS v3.0 / v3.1 base metric weights. v4 is stored only when a source gives a number.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR = {
    "N": (0.85, 0.85),
    "L": (0.62, 0.68),
    "H": (0.27, 0.50),
}


def ecosystem_name(raw: str | None) -> str | None:
    if not raw:
        return None
    return _ECOSYSTEMS.get(raw) or _ECOSYSTEMS.get(raw.strip())


def canonical_name(ecosystem: str, name: str) -> str:
    """PyPI names follow PEP 503. npm names are stored in lowercase.

    Maven `group:artifact` and Go module paths keep their case: Go paths are
    case-sensitive (`github.com/BurntSushi/toml`).
    """
    text = name.strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", text).lower()
    if ecosystem in {"maven", "golang"}:
        return text
    return text.lower()


def content_hash(body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def alias_pairs(identifiers: list[str]) -> list[tuple[str, str]]:
    """Every distinct id paired with every other id, in both directions."""
    ordered: list[str] = []
    seen: set[str] = set()
    for identifier in identifiers:
        if not isinstance(identifier, str):
            continue
        text = identifier.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    pairs: list[tuple[str, str]] = []
    for left in ordered:
        for right in ordered:
            if left != right:
                pairs.append((left, right))
    return pairs


def cvss3_score(vector: str) -> float | None:
    """Base score for a CVSS 3.0 or 3.1 vector. Returns None if it is not one."""
    if not vector or not vector.startswith("CVSS:3."):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key] = value
    try:
        attack = _AV[metrics["AV"]]
        complexity = _AC[metrics["AC"]]
        interaction = _UI[metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        privileges = _PR[metrics["PR"]][1 if scope_changed else 0]
        confidentiality = _CIA[metrics["C"]]
        integrity = _CIA[metrics["I"]]
        availability = _CIA[metrics["A"]]
    except KeyError:
        return None
    impact_sub = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
    if scope_changed:
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15
    else:
        impact = 6.42 * impact_sub
    exploitability = 8.22 * attack * complexity * privileges * interaction
    if impact <= 0:
        raw = 0.0
    elif scope_changed:
        raw = min(1.08 * (impact + exploitability), 10)
    else:
        raw = min(impact + exploitability, 10)
    return _roundup(raw)


def _roundup(value: float) -> float:
    """CVSS roundup: smallest one-decimal value that is not below `value`."""
    int_input = int(round(value * 100000))
    if int_input % 10000 == 0:
        return int_input / 100000
    return (math.floor(int_input / 10000) + 1) / 10


def vector_version(vector: str | None, fallback: str = "") -> str:
    if not vector:
        return fallback
    if vector.startswith("CVSS:"):
        rest = vector.split("/", 1)[0]
        return rest.split(":", 1)[1]
    return fallback
