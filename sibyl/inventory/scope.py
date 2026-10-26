"""SQL filters that keep a triage read inside one workspace."""

from __future__ import annotations

from sibyl.config import Settings
from sibyl.inventory.store import safe_id


def service_filter(settings: Settings | None, alias: str = "services") -> str:
    """` AND ...` limiting `alias` to active services, and to the settings' workspace when one is set.

    The workspace id is checked against the id grammar before it is put into SQL.
    """
    clause = f" AND {alias}.status = 'active'"
    workspace = (settings.workspace_id if settings is not None else "") or ""
    if workspace:
        if not safe_id(workspace):
            raise RuntimeError(f"workspace id {workspace!r} is not safe to interpolate")
        clause += f" AND {alias}.workspace_id = '{workspace}'"
    return clause
