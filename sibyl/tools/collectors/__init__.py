"""Run collectors and upsert normalised rows into evidence."""

from __future__ import annotations

from collections.abc import Sequence

import psycopg

from sibyl.config import Settings, load_settings
from sibyl.tools.collectors.base import Collector, SourceReport
from sibyl.tools.collectors.cve_org import CveOrgCollector
from sibyl.tools.collectors.epss import EpssCollector
from sibyl.tools.collectors.euvd import EuvdCollector
from sibyl.tools.collectors.ghsa import GhsaCollector
from sibyl.tools.collectors.kev import KevCollector
from sibyl.tools.collectors.migrate import ensure_evidence_schema
from sibyl.tools.collectors.nvd import NvdCollector
from sibyl.tools.collectors.osv import OsvCollector
from sibyl.tools.collectors.store import write_batch
from sibyl.tools.collectors.targets import workspace_cves

COLLECTORS: dict[str, Collector] = {
    collector.source: collector
    for collector in (
        OsvCollector(),
        GhsaCollector(),
        NvdCollector(),
        CveOrgCollector(),
        KevCollector(),
        EpssCollector(),
        EuvdCollector(),
    )
}


def ingest(
    sources: Sequence[str] | None = None,
    window: tuple[str, str] | None = None,
    settings: Settings | None = None,
) -> list[SourceReport]:
    """Collect `sources` (default: all seven) and upsert them.

    `window` is (since, until) for live GHSA and NVD queries. Snapshot mode
    reads the files already under `settings.snapshot_path()` and does not
    apply the window again. In live mode a source that still fails after two
    retries is loaded from that snapshot and reported as degraded.
    """
    active = settings or load_settings()
    if not active.database_url:
        raise RuntimeError("DATABASE_URL is empty")
    names = list(sources) if sources is not None else list(COLLECTORS)
    unknown = [name for name in names if name not in COLLECTORS]
    if unknown:
        raise RuntimeError("unknown sources: " + ", ".join(unknown))
    reports: list[SourceReport] = []
    try:
        with psycopg.connect(active.database_url) as conn:
            ensure_evidence_schema(conn)
            for name in names:
                batch = COLLECTORS[name].collect(active, window=window)
                reports.append(write_batch(conn, batch))
    except psycopg.Error as exc:
        raise RuntimeError(active.redact(str(exc))) from None
    return reports


def ingest_workspace(workspace_id: str, settings: Settings | None = None) -> list[SourceReport]:
    """Live ingest for one workspace's packages.

    OSV (purl query batch) and GHSA (`affects`) go first; their CVE aliases
    then decide which CVE.org and NVD records are fetched by id. EUVD's
    exploited list, KEV and EPSS are whole feeds. Evidence is a shared cache
    of public advisories, so records another workspace already fetched are
    upserted, not duplicated.
    """
    active = (settings or load_settings()).model_copy(update={"sample_mode": False, "workspace_id": workspace_id})
    reports = ingest(["osv", "ghsa"], settings=active)
    targeted = active.model_copy(update={"target_cves": workspace_cves(active)})
    reports.extend(ingest(["cve_org", "nvd", "euvd", "kev", "epss"], settings=targeted))
    return reports
