"""Component identity from a package URL.

`name` is the package name as the advisory sources store it, so that
`evidence.affected.package = inventory.components.name` joins:

- PyPI: PEP 503 (`Django_REST` → `django-rest`).
- npm: lowercase, with the scope (`@babel/core`).
- Maven: `group:artifact` (`org.apache.logging.log4j:log4j-core`).
- Go: the module path, case kept (`github.com/BurntSushi/toml`).

Other purl types are kept with their own type as the ecosystem and are not
covered by matching yet.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from packageurl import PackageURL

COVERED = ("npm", "pypi", "maven", "golang")


@dataclass(frozen=True)
class Component:
    purl: str
    ecosystem: str
    name: str
    version: str


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def component_name(ecosystem: str, namespace: str | None, name: str) -> str:
    if ecosystem == "pypi":
        return pep503(name)
    if ecosystem == "npm":
        full = f"{namespace}/{name}" if namespace else name
        return full.lower()
    if ecosystem == "maven":
        return f"{namespace}:{name}" if namespace else name
    if ecosystem == "golang":
        return f"{namespace}/{name}" if namespace else name
    return f"{namespace}/{name}" if namespace else name


def parse(purl: str, fallback_name: str = "", fallback_version: str = "") -> Component | None:
    """A component for a `pkg:` URL, or None when it does not parse."""
    if not purl.startswith("pkg:"):
        return None
    try:
        parsed = PackageURL.from_string(purl)
    except ValueError:
        return None
    ecosystem = (parsed.type or "").lower()
    name = parsed.name or fallback_name
    if not ecosystem or not name:
        return None
    return Component(
        purl=purl,
        ecosystem=ecosystem,
        name=component_name(ecosystem, parsed.namespace, name),
        version=parsed.version or fallback_version or "",
    )


def covered(ecosystem: str) -> bool:
    return ecosystem in COVERED
