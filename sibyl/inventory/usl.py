"""The inventory as a Zetaris Unified Semantic Layer model, with data-quality rules.

`lightning.metastore.sibyl.inventory` declares workspace, repository, service
and component with keys and descriptions, activated over the `inventory`
datasource. The descriptions are what an agent reads to understand the
schema. The data-quality rules run after every repository sync; a rule that
fails for the workspace becomes an inbox item.

`location` is a reserved word in USL DDL, so the repository column is `source_location`.
Checked live on Zetaris 2.4.3.1 (P7): compile, activate, select, join,
REGISTER DQ, RUN DQ and SHOW DQ INVALID RECORD all work over our Postgres.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from sibyl.config import Settings, load_settings
from sibyl.inventory.store import safe_id
from sibyl.tools.zetaris import run_admin

NAMESPACE = "lightning.metastore.sibyl"
USL = "inventory"
QUALIFIED = f"{NAMESPACE}.{USL}"

DDL = """CREATE TABLE workspace (
  workspace_id varchar(64) NOT NULL PRIMARY KEY,
  name varchar(200),
  is_demo boolean
);
CREATE TABLE repository (
  repo_id varchar(64) NOT NULL PRIMARY KEY,
  workspace_id varchar(64) FOREIGN KEY REFERENCES workspace(workspace_id),
  kind varchar(16),
  source_location varchar(1000),
  branch varchar(200),
  last_scanned_sha varchar(64),
  status varchar(32)
);
CREATE TABLE service (
  service_id varchar(128) NOT NULL PRIMARY KEY,
  workspace_id varchar(64) FOREIGN KEY REFERENCES workspace(workspace_id),
  repo_id varchar(64),
  name varchar(200),
  path varchar(1000),
  team varchar(200),
  internet_facing boolean,
  criticality double,
  data_class varchar(32),
  status varchar(16)
);
CREATE TABLE component (
  component_id varchar(1200) NOT NULL PRIMARY KEY,
  service_id varchar(128) FOREIGN KEY REFERENCES service(service_id),
  workspace_id varchar(64),
  purl varchar(1000),
  ecosystem varchar(32),
  name varchar(500),
  version varchar(200),
  direct boolean,
  source_file varchar(1000)
)"""

ACTIVATE = {
    "workspace": "SELECT COALESCE(workspace_id, '') AS workspace_id, name, is_demo FROM inventory.workspaces",
    "repository": (
        "SELECT COALESCE(repo_id, '') AS repo_id, workspace_id, kind, location AS source_location, branch, last_scanned_sha, status "
        "FROM inventory.repositories"
    ),
    "service": (
        "SELECT COALESCE(service_id, '') AS service_id, workspace_id, repo_id, name, path, team, internet_facing, "
        "CAST(criticality AS double) AS criticality, data_class, status FROM inventory.services"
    ),
    "component": (
        "SELECT COALESCE(c.component_id, '') AS component_id, b.service_id, s.workspace_id, c.purl, c.ecosystem, "
        "c.name, c.version, c.direct, c.source_file "
        "FROM inventory.components AS c "
        "JOIN inventory.sboms AS b ON c.sbom_id = b.sbom_id "
        "JOIN inventory.services AS s ON b.service_id = s.service_id"
    ),
}

DESCRIPTIONS = {
    "workspace": "One workspace: a set of connected repositories and their services. is_demo marks the sample workspace",
    "repository": "A connected code repository: a git URL Sibyl mirrors or a local folder, the branch it follows and the last commit scanned",
    "service": "A deployable service found in a repository (one directory with its own manifest) or added by hand, with the facts a person confirmed: team, internet_facing, criticality 0 to 1, data_class",
    "component": "One package version a service depends on, from its CycloneDX SBOM. name is the advisory-source package name: PEP 503 for PyPI, scoped for npm, group:artifact for Maven, module path for Go",
}


@dataclass(frozen=True)
class Rule:
    name: str
    table: str
    expression: str
    meaning: str


RULES = (
    Rule("purl_is_package_url", "component", "purl LIKE 'pkg:%'", "component has a package URL"),
    Rule("version_present", "component", "version IS NOT NULL AND length(trim(version)) > 0", "component has a version"),
    Rule(
        "ecosystem_covered",
        "component",
        "ecosystem IN ('npm', 'pypi', 'maven', 'golang')",
        "component is in an ecosystem Sibyl matches (npm, PyPI, Maven, Go)",
    ),
    Rule("owner_named", "service", "team IS NOT NULL AND length(trim(team)) > 0", "service names an owning team"),
    Rule("criticality_in_range", "service", "criticality >= 0 AND criticality <= 1", "criticality is between 0 and 1"),
    Rule(
        "data_class_known",
        "service",
        "data_class IN ('public', 'internal', 'employee', 'customer', 'merchant', 'cardholder', 'credentials', 'health')",
        "data class is one Sibyl knows",
    ),
)

_ready = False
_lock = threading.Lock()


def ensure_usl(settings: Settings | None = None, *, force: bool = False) -> dict[str, Any]:
    """Deploy and activate the model and register its rules. Cheap after the first call."""
    global _ready
    active = settings or load_settings()
    with _lock:
        if _ready and not force:
            return {"deployed": False, "activated": [], "rules": []}
        run_admin("CREATE NAMESPACE IF NOT EXISTS lightning.metastore", settings=active)
        run_admin(f"CREATE NAMESPACE IF NOT EXISTS {NAMESPACE}", settings=active)
        deployed = False
        if not _model_complete(active):
            try:
                run_admin(f"REMOVE USL {USL} NAMESPACE {NAMESPACE}", settings=active)
            except RuntimeError:
                pass
            run_admin(f"COMPILE USL {USL} DEPLOY NAMESPACE {NAMESPACE} DDL\n{DDL}", settings=active)
            deployed = True
        activated = []
        for table, query in ACTIVATE.items():
            run_admin(f"ACTIVATE USL TABLE {QUALIFIED}.{table} AS {query}", settings=active)
            run_admin(f"UPDATE USL {QUALIFIED}.{table} SET TABLE DESCRIPTION {DESCRIPTIONS[table]}", settings=active)
            activated.append(table)
        existing = {row.get("name", "") for row in run_admin(f"LIST DQ USL {QUALIFIED}", settings=active).rows}
        registered = []
        for rule in RULES:
            if rule.name in existing:
                continue
            run_admin(f"REGISTER DQ {rule.name} TABLE {QUALIFIED}.{rule.table} AS {rule.expression}", settings=active)
            registered.append(rule.name)
        _ready = True
        return {"deployed": deployed, "activated": activated, "rules": registered}


def _model_complete(settings: Settings) -> bool:
    try:
        rows = run_admin(f"LOAD USL {USL} NAMESPACE {NAMESPACE}", settings=settings).rows
    except RuntimeError:
        return False
    text = " ".join(row.get("json", "") for row in rows)
    return all(f'"name":"{table}"' in text.replace(" ", "") for table in ACTIVATE) and "source_file" in text


def run_quality(workspace_id: str, settings: Settings | None = None) -> list[dict[str, Any]]:
    """Run every rule. Returns one entry per rule with the workspace's failing rows (up to 5 shown)."""
    if not safe_id(workspace_id):
        raise ValueError("unsafe workspace id")
    active = settings or load_settings()
    ensure_usl(active)
    results: list[dict[str, Any]] = []
    for rule in RULES:
        entry: dict[str, Any] = {"rule": rule.name, "table": rule.table, "meaning": rule.meaning, "invalid": 0, "examples": []}
        try:
            counted = run_admin(f"RUN DQ {rule.name} TABLE {QUALIFIED}.{rule.table}", settings=active).rows
        except RuntimeError as exc:
            entry["error"] = str(exc)[:300]
            results.append(entry)
            continue
        invalid_all = int(float((counted[0] if counted else {}).get("invalid_record") or 0))
        entry["checked"] = int(float((counted[0] if counted else {}).get("total_record") or 0))
        if invalid_all:
            rows = run_admin(f"SHOW DQ INVALID RECORD {rule.name} TABLE {QUALIFIED}.{rule.table}", settings=active, limit=5000).rows
            mine = [row for row in rows if row.get("workspace_id") == workspace_id and row.get("status", "active") in {"", "active"}]
            entry["invalid"] = len(mine)
            entry["examples"] = [_example(rule.table, row) for row in mine[:5]]
        results.append(entry)
    return results


def _example(table: str, row: dict[str, str]) -> str:
    if table == "component":
        return f"{row.get('purl') or row.get('name')} ({row.get('source_file') or row.get('service_id')})"
    return f"{row.get('name') or row.get('service_id')} ({row.get('path') or 'no path'})"
