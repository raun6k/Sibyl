"""Deterministic version-range checks.

`univers` parses PyPI (PEP 440), npm (semver), Maven and Go versions. This
module does not implement its own version order. GHSA writes Maven and Go
ranges as comparators (`>= 2.0, < 2.15.0`), which univers' native Maven and
Go parsers do not read, so those are split into constraints here. `None` means the inputs are not enough
to decide: no range, or a bound that will not parse.
"""

from __future__ import annotations

import re

from univers.version_constraint import VersionConstraint
from univers.version_range import GolangVersionRange, MavenVersionRange, NpmVersionRange, PypiVersionRange
from univers.versions import GolangVersion, MavenVersion, PypiVersion, SemverVersion

_CLASSES = {
    "pypi": (PypiVersion, PypiVersionRange),
    "npm": (SemverVersion, NpmVersionRange),
    "maven": (MavenVersion, MavenVersionRange),
    "golang": (GolangVersion, GolangVersionRange),
}
_COMPARATOR_ONLY = {"maven", "golang"}
_COMPARATOR = re.compile(r"^\s*(>=|<=|==|=|>|<)\s*([^\s,]+)\s*$")
_OPEN = {"0", "0.0.0", "0.0.0.0"}


def is_affected(ecosystem: str, version: str, ranges: list[dict] | None) -> bool | None:
    """Return whether `version` falls in any range.

    A range matches on its GHSA-style `raw_range` when that string is a
    comparator expression (`>= 1.0, < 1.2.3`). Otherwise the structured
    bounds are used: `introduced` is inclusive, `fixed` is exclusive,
    `last_affected` is inclusive. `introduced` of `0` means there is no
    lower bound. Any matching range makes the version affected. A mix of
    "not affected" and unparseable ranges stays undecided.
    """
    if not ranges:
        return None
    pair = _CLASSES.get(ecosystem)
    if pair is None or not version or not str(version).strip():
        return None
    version_class, _range_class = pair
    try:
        parsed = version_class(version)
    except (ValueError, TypeError):
        return None
    saw_false = False
    saw_unknown = False
    for item in ranges:
        result = _one(ecosystem, parsed, item or {})
        if result is True:
            return True
        if result is False:
            saw_false = True
        else:
            saw_unknown = True
    if saw_unknown or not saw_false:
        return None
    return False


def _one(ecosystem: str, parsed, item: dict) -> bool | None:
    if item.get("range_type") == "GIT":
        return None
    raw = str(item.get("raw_range") or "").strip()
    if _is_specifier(raw):
        native = _native(ecosystem, raw)
        if native is not None:
            try:
                return parsed in native
            except TypeError:
                return None
    return _structured(ecosystem, parsed, item)


def _is_specifier(raw: str) -> bool:
    if not raw or raw[0] in "{[":
        return False
    if raw.startswith("cpe:"):
        return False
    return any(token in raw for token in (">=", "<=", ">", "<", "="))


def _native(ecosystem: str, raw: str):
    version_class, range_class = _CLASSES[ecosystem]
    if ecosystem in _COMPARATOR_ONLY:
        return _comparators(version_class, range_class, raw)
    text = raw
    if ecosystem == "npm":
        text = " ".join(raw.replace(",", " ").split())
    try:
        return range_class.from_native(text)
    except (ValueError, TypeError):
        return None


def _comparators(version_class, range_class, raw: str):
    """`>= 1.0, < 1.2.3` as a range, or None when any part does not parse."""
    constraints = []
    for part in raw.split(","):
        if not part.strip():
            continue
        match = _COMPARATOR.match(part)
        if match is None:
            return None
        comparator = "=" if match.group(1) == "==" else match.group(1)
        try:
            constraints.append(VersionConstraint(comparator=comparator, version=version_class(match.group(2))))
        except (ValueError, TypeError):
            return None
    if not constraints:
        return None
    try:
        return range_class(constraints=constraints)
    except (ValueError, TypeError):
        return None


def _structured(ecosystem: str, parsed, item: dict) -> bool | None:
    version_class, range_class = _CLASSES[ecosystem]
    introduced = _blank(item.get("introduced"))
    fixed = _blank(item.get("fixed"))
    last_affected = _blank(item.get("last_affected"))
    raw = str(item.get("raw_range") or "")
    open_ended = introduced in _OPEN
    exclusive_lower = bool(introduced) and f"start_excluding={introduced}" in raw
    if open_ended:
        introduced = None
    if not introduced and not fixed and not last_affected:
        return True if open_ended else None
    # >=X together with <=X sorts into a vers pair that matches every version.
    # An exact version is a single "=" constraint.
    exact = bool(introduced) and introduced == last_affected and not fixed and not exclusive_lower
    constraints = []
    try:
        if exact:
            constraints.append(VersionConstraint(comparator="=", version=version_class(introduced)))
        else:
            if introduced:
                comparator = ">" if exclusive_lower else ">="
                constraints.append(
                    VersionConstraint(comparator=comparator, version=version_class(introduced))
                )
            if fixed:
                constraints.append(VersionConstraint(comparator="<", version=version_class(fixed)))
            if last_affected:
                constraints.append(
                    VersionConstraint(comparator="<=", version=version_class(last_affected))
                )
    except (ValueError, TypeError):
        return None
    if not constraints:
        return True if open_ended else None
    try:
        return parsed in range_class(constraints=constraints)
    except (TypeError, ValueError):
        return None


def _blank(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
