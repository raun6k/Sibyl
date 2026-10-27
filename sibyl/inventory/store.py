"""Inventory writes and the app's own reads (workspaces, repositories, questions, syncs).

Triage reads services and components through Zetaris. These functions are
the management side: creating and changing the rows that Zetaris then reads.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row

from sibyl.config import Settings, load_settings
from sibyl.inventory.purls import Component
from sibyl.inventory.schema import ensure_inventory_schema

FACT_FIELDS = ("internet_facing", "team", "criticality", "data_class")
POLICIES = ("interval", "on_change", "manual")
_SLUG = re.compile(r"[^a-z0-9]+")
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


class NotFound(LookupError):
    pass


@dataclass
class ComponentDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, list[str]]:
        return {"added": self.added, "removed": self.removed, "changed": self.changed}

    @property
    def empty(self) -> bool:
        return not (self.added or self.removed or self.changed)


def slug(text: str, fallback: str = "item") -> str:
    """A lowercase id made of letters, digits and dashes. Safe to put in SQL."""
    value = _SLUG.sub("-", text.lower()).strip("-")[:48].strip("-")
    return value or fallback


def safe_id(value: str) -> bool:
    return bool(_SAFE_ID.fullmatch(value or ""))


def connect(settings: Settings | None = None) -> psycopg.Connection:
    active = settings or load_settings()
    if not active.database_url:
        raise RuntimeError("DATABASE_URL is empty")
    conn = psycopg.connect(active.database_url, row_factory=dict_row)
    return conn


def ensure(settings: Settings | None = None) -> None:
    with connect(settings) as conn:
        ensure_inventory_schema(conn)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _unique(conn: psycopg.Connection, table: str, column: str, base: str) -> str:
    candidate = base
    suffix = 2
    while conn.execute(f"SELECT 1 FROM inventory.{table} WHERE {column} = %s", (candidate,)).fetchone():
        candidate = f"{base[:58]}-{suffix}"
        suffix += 1
    return candidate


def _json(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    out: dict[str, Any] = {}
    for key, value in row.items():
        out[key] = value.isoformat() if isinstance(value, datetime) else value
    return out


# Workspaces ---------------------------------------------------------------


def list_workspaces(settings: Settings | None = None) -> list[dict[str, Any]]:
    with connect(settings) as conn:
        rows = conn.execute(
            """
            SELECT w.workspace_id, w.name, w.is_demo, w.created_at, w.settings,
                   (SELECT count(*) FROM inventory.services s
                     WHERE s.workspace_id = w.workspace_id AND s.status = 'active') AS services,
                   (SELECT count(*) FROM inventory.repositories r WHERE r.workspace_id = w.workspace_id) AS repositories,
                   (SELECT count(*) FROM inventory.questions q
                     WHERE q.workspace_id = w.workspace_id AND q.status = 'open') AS open_questions
            FROM inventory.workspaces w
            ORDER BY w.is_demo, w.created_at
            """
        ).fetchall()
    return [_json(row) for row in rows]  # type: ignore[misc]


def get_workspace(workspace_id: str, settings: Settings | None = None) -> dict[str, Any]:
    with connect(settings) as conn:
        row = conn.execute("SELECT * FROM inventory.workspaces WHERE workspace_id = %s", (workspace_id,)).fetchone()
    if row is None:
        raise NotFound(f"unknown workspace {workspace_id}")
    return _json(row)  # type: ignore[return-value]


def create_workspace(name: str, *, is_demo: bool = False, workspace_id: str | None = None, settings: Settings | None = None) -> dict[str, Any]:
    clean = name.strip() or "Workspace"
    with connect(settings) as conn:
        ident = workspace_id or _unique(conn, "workspaces", "workspace_id", slug(clean, "workspace"))
        conn.execute(
            """
            INSERT INTO inventory.workspaces (workspace_id, name, is_demo)
            VALUES (%s, %s, %s)
            ON CONFLICT (workspace_id) DO UPDATE SET name = EXCLUDED.name
            """,
            (ident, clean, is_demo),
        )
    return get_workspace(ident, settings)


def rename_workspace(workspace_id: str, name: str, settings: Settings | None = None) -> dict[str, Any]:
    with connect(settings) as conn:
        updated = conn.execute(
            "UPDATE inventory.workspaces SET name = %s WHERE workspace_id = %s",
            (name.strip() or "Workspace", workspace_id),
        )
        if updated.rowcount == 0:
            raise NotFound(f"unknown workspace {workspace_id}")
    return get_workspace(workspace_id, settings)


def update_workspace_settings(workspace_id: str, changes: dict[str, Any], settings: Settings | None = None) -> dict[str, Any]:
    """Merge keys into the workspace's settings (for example `feed_refresh_minutes`)."""
    with connect(settings) as conn:
        updated = conn.execute(
            "UPDATE inventory.workspaces SET settings = settings || %s::jsonb WHERE workspace_id = %s",
            (json.dumps(changes), workspace_id),
        )
        if updated.rowcount == 0:
            raise NotFound(f"unknown workspace {workspace_id}")
    return get_workspace(workspace_id, settings)


def delete_workspace(workspace_id: str, settings: Settings | None = None) -> None:
    with connect(settings) as conn:
        if not conn.execute("SELECT 1 FROM inventory.workspaces WHERE workspace_id = %s", (workspace_id,)).fetchone():
            raise NotFound(f"unknown workspace {workspace_id}")
        services = [row["service_id"] for row in conn.execute(
            "SELECT service_id FROM inventory.services WHERE workspace_id = %s", (workspace_id,)
        ).fetchall()]
        _delete_services(conn, services)
        conn.execute("DELETE FROM inventory.workspaces WHERE workspace_id = %s", (workspace_id,))


# Repositories -------------------------------------------------------------


def list_repositories(workspace_id: str, settings: Settings | None = None) -> list[dict[str, Any]]:
    with connect(settings) as conn:
        rows = conn.execute(
            """
            SELECT r.*,
                   (SELECT count(*) FROM inventory.services s
                     WHERE s.repo_id = r.repo_id AND s.status = 'active') AS services
            FROM inventory.repositories r
            WHERE r.workspace_id = %s
            ORDER BY r.created_at
            """,
            (workspace_id,),
        ).fetchall()
    return [_json(row) for row in rows]  # type: ignore[misc]


def get_repository(repo_id: str, settings: Settings | None = None) -> dict[str, Any]:
    with connect(settings) as conn:
        row = conn.execute("SELECT * FROM inventory.repositories WHERE repo_id = %s", (repo_id,)).fetchone()
    if row is None:
        raise NotFound(f"unknown repository {repo_id}")
    return _json(row)  # type: ignore[return-value]


def create_repository(
    workspace_id: str,
    *,
    kind: str,
    location: str,
    branch: str = "main",
    token_env: str = "",
    sync_interval_minutes: int = 60,
    settings: Settings | None = None,
) -> dict[str, Any]:
    base = slug(location.rstrip("/").split("/")[-1].removesuffix(".git"), "repo")
    with connect(settings) as conn:
        if not conn.execute("SELECT 1 FROM inventory.workspaces WHERE workspace_id = %s", (workspace_id,)).fetchone():
            raise NotFound(f"unknown workspace {workspace_id}")
        repo_id = _unique(conn, "repositories", "repo_id", base)
        conn.execute(
            """
            INSERT INTO inventory.repositories
                (repo_id, workspace_id, kind, location, branch, token_env, sync_interval_minutes)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (repo_id, workspace_id, kind, location, branch or "main", token_env, sync_interval_minutes),
        )
    return get_repository(repo_id, settings)


def update_repository(repo_id: str, changes: dict[str, Any], settings: Settings | None = None) -> dict[str, Any]:
    allowed = {"branch", "token_env", "sync_interval_minutes", "last_scanned_sha", "last_synced_at", "status", "error"}
    fields = {key: value for key, value in changes.items() if key in allowed}
    if fields:
        assignments = ", ".join(f"{key} = %s" for key in fields)
        with connect(settings) as conn:
            updated = conn.execute(
                f"UPDATE inventory.repositories SET {assignments} WHERE repo_id = %s",
                (*fields.values(), repo_id),
            )
            if updated.rowcount == 0:
                raise NotFound(f"unknown repository {repo_id}")
    return get_repository(repo_id, settings)


def delete_repository(repo_id: str, settings: Settings | None = None) -> None:
    """Remove the repository and every service found in it."""
    with connect(settings) as conn:
        if not conn.execute("SELECT 1 FROM inventory.repositories WHERE repo_id = %s", (repo_id,)).fetchone():
            raise NotFound(f"unknown repository {repo_id}")
        services = [row["service_id"] for row in conn.execute(
            "SELECT service_id FROM inventory.services WHERE repo_id = %s", (repo_id,)
        ).fetchall()]
        _delete_services(conn, services)
        conn.execute("DELETE FROM inventory.questions WHERE repo_id = %s", (repo_id,))
        conn.execute("DELETE FROM inventory.repositories WHERE repo_id = %s", (repo_id,))


# Services -----------------------------------------------------------------


def list_services(workspace_id: str, settings: Settings | None = None, *, include_removed: bool = False) -> list[dict[str, Any]]:
    status = "" if include_removed else "AND s.status = 'active'"
    with connect(settings) as conn:
        rows = conn.execute(
            f"""
            SELECT s.*,
                   (SELECT count(*) FROM inventory.components c JOIN inventory.sboms b ON c.sbom_id = b.sbom_id
                     WHERE b.service_id = s.service_id) AS components,
                   (SELECT max(b.generated_at) FROM inventory.sboms b WHERE b.service_id = s.service_id) AS sbom_at,
                   (SELECT coalesce(json_object_agg(e.ecosystem, e.n), '{{}}'::json) FROM (
                      SELECT c.ecosystem, count(*) AS n FROM inventory.components c
                      JOIN inventory.sboms b ON c.sbom_id = b.sbom_id
                      WHERE b.service_id = s.service_id GROUP BY c.ecosystem) e) AS ecosystems
            FROM inventory.services s
            WHERE s.workspace_id = %s {status}
            ORDER BY s.name
            """,
            (workspace_id,),
        ).fetchall()
    return [_json(row) for row in rows]  # type: ignore[misc]


def get_service(service_id: str, settings: Settings | None = None) -> dict[str, Any]:
    with connect(settings) as conn:
        row = conn.execute("SELECT * FROM inventory.services WHERE service_id = %s", (service_id,)).fetchone()
    if row is None:
        raise NotFound(f"unknown service {service_id}")
    return _json(row)  # type: ignore[return-value]


def services_for_repo(repo_id: str, settings: Settings | None = None) -> list[dict[str, Any]]:
    with connect(settings) as conn:
        rows = conn.execute(
            "SELECT * FROM inventory.services WHERE repo_id = %s AND status = 'active' ORDER BY path",
            (repo_id,),
        ).fetchall()
    return [_json(row) for row in rows]  # type: ignore[misc]


def create_service(
    workspace_id: str,
    name: str,
    *,
    repo_id: str | None = None,
    path: str = "",
    facts: dict[str, Any] | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    values = {"team": "", "internet_facing": False, "criticality": 0.5, "data_class": "internal"}
    values.update({key: value for key, value in (facts or {}).items() if key in FACT_FIELDS and value is not None})
    with connect(settings) as conn:
        if not conn.execute("SELECT 1 FROM inventory.workspaces WHERE workspace_id = %s", (workspace_id,)).fetchone():
            raise NotFound(f"unknown workspace {workspace_id}")
        base = slug(f"{repo_id}-{name}" if repo_id and name != repo_id else name, "service")
        service_id = _unique(conn, "services", "service_id", base)
        conn.execute(
            """
            INSERT INTO inventory.services
                (service_id, name, team, internet_facing, criticality, data_class, workspace_id, repo_id, path, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'active')
            """,
            (
                service_id,
                name.strip() or service_id,
                str(values["team"]),
                bool(values["internet_facing"]),
                float(values["criticality"]),
                str(values["data_class"]),
                workspace_id,
                repo_id,
                path,
            ),
        )
    return get_service(service_id, settings)


def update_service(service_id: str, changes: dict[str, Any], settings: Settings | None = None) -> dict[str, Any]:
    allowed = set(FACT_FIELDS) | {"name", "triage_policy", "triage_interval_minutes", "status"}
    fields = {key: value for key, value in changes.items() if key in allowed and value is not None}
    if "triage_policy" in fields and fields["triage_policy"] not in POLICIES:
        raise ValueError("triage_policy must be interval, on_change or manual")
    if "criticality" in fields:
        fields["criticality"] = max(0.0, min(1.0, float(fields["criticality"])))
    if "internet_facing" in fields:
        fields["internet_facing"] = _as_bool(fields["internet_facing"])
    if fields:
        assignments = ", ".join(f"{key} = %s" for key in fields)
        with connect(settings) as conn:
            updated = conn.execute(
                f"UPDATE inventory.services SET {assignments} WHERE service_id = %s",
                (*fields.values(), service_id),
            )
            if updated.rowcount == 0:
                raise NotFound(f"unknown service {service_id}")
    return get_service(service_id, settings)


def remove_service(service_id: str, settings: Settings | None = None) -> None:
    with connect(settings) as conn:
        if not conn.execute("SELECT 1 FROM inventory.services WHERE service_id = %s", (service_id,)).fetchone():
            raise NotFound(f"unknown service {service_id}")
        _delete_services(conn, [service_id])


def _delete_services(conn: psycopg.Connection, service_ids: Sequence[str]) -> None:
    if not service_ids:
        return
    ids = list(service_ids)
    conn.execute(
        "DELETE FROM inventory.components WHERE sbom_id IN (SELECT sbom_id FROM inventory.sboms WHERE service_id = ANY(%s))",
        (ids,),
    )
    conn.execute("DELETE FROM inventory.sboms WHERE service_id = ANY(%s)", (ids,))
    conn.execute("DELETE FROM inventory.questions WHERE service_id = ANY(%s)", (ids,))
    conn.execute("DELETE FROM inventory.services WHERE service_id = ANY(%s)", (ids,))


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "t", "yes", "y"}


# Components ---------------------------------------------------------------


def replace_components(
    service_id: str,
    components: Iterable[tuple[Component, bool, str]],
    *,
    sbom_format: str = "CycloneDX/1.6",
    source: str = "",
    commit_sha: str | None = None,
    settings: Settings | None = None,
) -> ComponentDiff:
    """Make the service's one SBOM hold exactly `components` (component, direct, source_file).

    Returns what changed against the previous set, by purl without version.
    """
    sbom_id = f"sbom-{service_id}"
    wanted: dict[str, tuple[Component, bool, str]] = {}
    for component, direct, source_file in components:
        wanted.setdefault(component.purl, (component, direct, source_file))
    with connect(settings) as conn:
        previous = {
            row["purl"]: row
            for row in conn.execute(
                "SELECT c.purl, c.ecosystem, c.name, c.version FROM inventory.components c WHERE c.sbom_id = %s",
                (sbom_id,),
            ).fetchall()
        }
        conn.execute(
            """
            INSERT INTO inventory.sboms (sbom_id, service_id, format, generated_at, source_lockfile, commit_sha)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (sbom_id) DO UPDATE SET
                format = EXCLUDED.format, generated_at = EXCLUDED.generated_at,
                source_lockfile = EXCLUDED.source_lockfile, commit_sha = EXCLUDED.commit_sha
            """,
            (sbom_id, service_id, sbom_format, _now(), source, commit_sha),
        )
        conn.execute("DELETE FROM inventory.components WHERE sbom_id = %s", (sbom_id,))
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO inventory.components
                    (component_id, sbom_id, purl, ecosystem, name, version, direct, source_file)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                [
                    (f"{sbom_id}|{purl}", sbom_id, purl, item.ecosystem, item.name, item.version, direct, source_file)
                    for purl, (item, direct, source_file) in wanted.items()
                ],
            )
    return diff_components(
        [(row["ecosystem"], row["name"], row["version"]) for row in previous.values()],
        [(item.ecosystem, item.name, item.version) for item, _direct, _file in wanted.values()],
    )


def components_for(service_id: str, settings: Settings | None = None) -> list[tuple[Component, bool, str]]:
    with connect(settings) as conn:
        rows = conn.execute(
            """
            SELECT c.purl, c.ecosystem, c.name, c.version, c.direct, c.source_file
            FROM inventory.components c JOIN inventory.sboms b ON c.sbom_id = b.sbom_id
            WHERE b.service_id = %s
            """,
            (service_id,),
        ).fetchall()
    return [
        (Component(purl=row["purl"], ecosystem=row["ecosystem"], name=row["name"], version=row["version"]), bool(row["direct"]), row["source_file"] or "")
        for row in rows
    ]


def diff_components(before: Iterable[tuple[str, str, str]], after: Iterable[tuple[str, str, str]]) -> ComponentDiff:
    """Compare (ecosystem, name, version) sets by package; a new version is `changed`."""
    old: dict[tuple[str, str], set[str]] = {}
    new: dict[tuple[str, str], set[str]] = {}
    for ecosystem, name, version in before:
        old.setdefault((ecosystem, name), set()).add(version)
    for ecosystem, name, version in after:
        new.setdefault((ecosystem, name), set()).add(version)
    result = ComponentDiff()
    for key in sorted(new):
        label = f"{key[0]}:{key[1]}"
        if key not in old:
            result.added.append(f"{label}@{','.join(sorted(new[key]))}")
        elif new[key] != old[key]:
            result.changed.append(f"{label} {','.join(sorted(old[key]))} -> {','.join(sorted(new[key]))}")
    for key in sorted(old):
        if key not in new:
            result.removed.append(f"{key[0]}:{key[1]}@{','.join(sorted(old[key]))}")
    return result


# Questions ----------------------------------------------------------------


def add_question(
    workspace_id: str,
    *,
    kind: str,
    prompt: str,
    service_id: str | None = None,
    repo_id: str | None = None,
    field: str = "",
    proposed: Any = None,
    evidence: list[dict[str, Any]] | None = None,
    confidence: float = 0.0,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Open a question, or refresh the open one for the same service, kind and field."""
    with connect(settings) as conn:
        existing = conn.execute(
            """
            SELECT question_id FROM inventory.questions
            WHERE workspace_id = %s AND status = 'open' AND kind = %s AND field = %s
              AND coalesce(service_id, '') = %s AND coalesce(repo_id, '') = %s
            """,
            (workspace_id, kind, field, service_id or "", repo_id or ""),
        ).fetchone()
        payload = (prompt, json.dumps(proposed), json.dumps(evidence or []), confidence)
        if existing:
            question_id = existing["question_id"]
            conn.execute(
                """
                UPDATE inventory.questions SET prompt = %s, proposed = %s, evidence = %s, confidence = %s, created_at = now()
                WHERE question_id = %s
                """,
                (*payload, question_id),
            )
        else:
            question_id = "q-" + uuid.uuid4().hex[:12]
            conn.execute(
                """
                INSERT INTO inventory.questions
                    (question_id, workspace_id, service_id, repo_id, kind, field, prompt, proposed, evidence, confidence)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (question_id, workspace_id, service_id, repo_id, kind, field, *payload),
            )
    return get_question(question_id, settings)


def get_question(question_id: str, settings: Settings | None = None) -> dict[str, Any]:
    with connect(settings) as conn:
        row = conn.execute("SELECT * FROM inventory.questions WHERE question_id = %s", (question_id,)).fetchone()
    if row is None:
        raise NotFound(f"unknown question {question_id}")
    return _json(row)  # type: ignore[return-value]


def list_questions(workspace_id: str, status: str = "open", settings: Settings | None = None) -> list[dict[str, Any]]:
    with connect(settings) as conn:
        rows = conn.execute(
            """
            SELECT q.*, s.name AS service_name, s.path AS service_path
            FROM inventory.questions q
            LEFT JOIN inventory.services s ON s.service_id = q.service_id
            WHERE q.workspace_id = %s AND (%s = 'all' OR q.status = %s)
            ORDER BY q.created_at DESC
            """,
            (workspace_id, status, status),
        ).fetchall()
    return [_json(row) for row in rows]  # type: ignore[misc]


def close_question(question_id: str, *, status: str, answer: Any, user: str, settings: Settings | None = None) -> dict[str, Any]:
    with connect(settings) as conn:
        updated = conn.execute(
            """
            UPDATE inventory.questions SET status = %s, answer = %s, answered_by = %s, answered_at = now()
            WHERE question_id = %s
            """,
            (status, json.dumps(answer), user, question_id),
        )
        if updated.rowcount == 0:
            raise NotFound(f"unknown question {question_id}")
    return get_question(question_id, settings)


def close_questions_for(
    service_id: str,
    kinds: Sequence[str],
    settings: Settings | None = None,
    *,
    fields: Sequence[str] | None = None,
    user: str = "sibyl",
) -> None:
    """Close open questions a person has settled some other way (an edit, a removal)."""
    with connect(settings) as conn:
        conn.execute(
            """
            UPDATE inventory.questions SET status = 'answered', answered_by = %s, answered_at = now(),
                   answer = '{"action": "settled elsewhere"}'::jsonb
            WHERE service_id = %s AND kind = ANY(%s) AND status = 'open'
              AND (%s::text[] IS NULL OR field = ANY(%s::text[]))
            """,
            (user, service_id, list(kinds), list(fields) if fields else None, list(fields) if fields else None),
        )


# Syncs --------------------------------------------------------------------


def start_sync(repo_id: str, workspace_id: str, from_sha: str | None, mode: str, settings: Settings | None = None) -> str:
    sync_id = "sync-" + uuid.uuid4().hex[:12]
    with connect(settings) as conn:
        conn.execute(
            """
            INSERT INTO inventory.repo_syncs (sync_id, repo_id, workspace_id, from_sha, mode)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (sync_id, repo_id, workspace_id, from_sha, mode),
        )
    return sync_id


def finish_sync(
    sync_id: str,
    *,
    status: str,
    to_sha: str | None = None,
    mode: str | None = None,
    summary: dict[str, Any] | None = None,
    error: str = "",
    settings: Settings | None = None,
) -> None:
    with connect(settings) as conn:
        conn.execute(
            """
            UPDATE inventory.repo_syncs
            SET status = %s, to_sha = %s, summary = %s, error = %s, finished_at = now(), mode = coalesce(%s, mode)
            WHERE sync_id = %s
            """,
            (status, to_sha, json.dumps(summary or {}), error, mode, sync_id),
        )


def list_syncs(*, workspace_id: str | None = None, repo_id: str | None = None, limit: int = 20, settings: Settings | None = None) -> list[dict[str, Any]]:
    with connect(settings) as conn:
        rows = conn.execute(
            """
            SELECT * FROM inventory.repo_syncs
            WHERE (%s::text IS NULL OR workspace_id = %s) AND (%s::text IS NULL OR repo_id = %s)
            ORDER BY started_at DESC
            LIMIT %s
            """,
            (workspace_id, workspace_id, repo_id, repo_id, limit),
        ).fetchall()
    return [_json(row) for row in rows]  # type: ignore[misc]


def workspace_purls(workspace_id: str, settings: Settings | None = None) -> list[str]:
    with connect(settings) as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT c.purl FROM inventory.components c
            JOIN inventory.sboms b ON c.sbom_id = b.sbom_id
            JOIN inventory.services s ON b.service_id = s.service_id
            WHERE s.workspace_id = %s AND s.status = 'active' AND c.purl LIKE 'pkg:%%'
            ORDER BY c.purl
            """,
            (workspace_id,),
        ).fetchall()
    return [row["purl"] for row in rows]
