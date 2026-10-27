"""The inventory over time, in the World Model.

Each service has one `uses` edge per package, slotted by the purl without
its version: `service:<id> —uses→ component:<purl@version>`, valid from the
commit time of the scan that found it. A new version closes the old edge;
a package that is gone has its edge closed. "What did checkout-api run on
3 October" is `edges("service:checkout-api", via="uses", at=...)`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sibyl.config import Settings
from sibyl.inventory import store
from sibyl.inventory.purls import purl_slot


def service_entity(service_id: str) -> str:
    return f"service:{service_id}"


def component_entity(purl: str) -> str:
    return f"component:{purl}"


def sync_service_edges(world: Any, service_id: str, *, at: str = "", source: str = "repo_sync", settings: Settings | None = None) -> dict[str, int]:
    """Make the open edges match the service's current components. Returns opened and closed counts."""
    when = at or datetime.now(timezone.utc).isoformat()
    purls = sorted({component.purl for component, _direct, _file in store.components_for(service_id, settings)})
    return apply_edges(world, service_id, purls, at=when, source=source)


def apply_edges(world: Any, service_id: str, purls: list[str], *, at: str, source: str) -> dict[str, int]:
    origin = {"kind": source, "at": at}
    entity = service_entity(service_id)
    current = {str(edge.get("slot") or ""): edge for edge in world.edges(entity, via="uses")}
    wanted: dict[str, str] = {}
    for purl in purls:
        wanted.setdefault(purl_slot(purl), purl)
    opened = 0
    closed = 0
    for slot, purl in sorted(wanted.items()):
        if (current.get(slot) or {}).get("to") == component_entity(purl):
            continue
        result = world.relate(from_id=entity, type="uses", to=component_entity(purl), valid_from=at, source=origin, slot=slot)
        opened += 1 if result.get("changed") else 0
    for slot in sorted(set(current) - set(wanted)):
        result = world.unrelate(from_id=entity, type="uses", valid_to=at, source=origin, slot=slot)
        closed += 1 if result.get("changed") else 0
    return {"opened": opened, "closed": closed}


def close_service_edges(world: Any, service_id: str, *, at: str = "") -> int:
    """A removed service no longer uses anything."""
    when = at or datetime.now(timezone.utc).isoformat()
    return apply_edges(world, service_id, [], at=when, source="service_removed")["closed"]


def demo_edges(world: Any, workspace_id: str, settings: Settings | None = None) -> dict[str, int]:
    """The demo workspace's edges, valid from each sample SBOM's own timestamp (stable across reseeds)."""
    totals = {"opened": 0, "closed": 0}
    with store.connect(settings) as conn:
        rows = conn.execute(
            "SELECT s.service_id, max(b.generated_at) AS at FROM inventory.services s "
            "LEFT JOIN inventory.sboms b ON b.service_id = s.service_id "
            "WHERE s.workspace_id = %s AND s.status = 'active' GROUP BY s.service_id ORDER BY s.service_id",
            (workspace_id,),
        ).fetchall()
    for row in rows:
        at = row["at"].isoformat() if row["at"] is not None else ""
        counts = sync_service_edges(world, row["service_id"], at=at, source="demo_seed", settings=settings)
        totals["opened"] += counts["opened"]
        totals["closed"] += counts["closed"]
    return totals
