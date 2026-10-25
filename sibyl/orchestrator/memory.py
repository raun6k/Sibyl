"""Human resolutions and pending H-MEM changes.

The API and the rerun check both call `resolve_case`. A `this_case`
resolution is stored immediately. `adjust_trust` only queues a preview.
"""

from __future__ import annotations

from typing import Any

from sibyl.engines.hmem import HmemClient


def resolve_case(
    hmem: HmemClient,
    *,
    case_id: str,
    decision: str,
    note: str,
    user: str,
    remember: bool,
    scope: str,
    method: str = "",
    ecosystem: str = "*",
    package: str = "",
    vuln_id: str = "",
) -> dict[str, Any]:
    source = "cna" if method == "text_llm" else "osv"
    return hmem.resolve(
        {
            "case_id": case_id,
            "decision": decision,
            "note": note,
            "user": user,
            "remember": remember,
            "scope": scope,
            "source": source,
            "field": "affected_ranges",
            "ecosystem": ecosystem or "*",
            "package": package,
            "vuln_id": vuln_id,
        }
    )
