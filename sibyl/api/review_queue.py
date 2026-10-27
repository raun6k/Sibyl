"""Keep already-resolved cases out of human review without changing run reports."""
from __future__ import annotations

from typing import Any, Protocol


class ResolutionStore(Protocol):
    def resolution_for(self, case_id: str) -> dict[str, Any] | None: ...


def unresolved_cases(cards: list[dict[str, Any]], memory: ResolutionStore) -> list[dict[str, Any]]:
    """H-MEM applies resolution expiry and scope; pending trust proposals are not resolutions.

    If memory cannot be read, leave the case visible rather than hiding uncertain work.
    """
    unresolved = []
    for card in cards:
        try:
            resolution = memory.resolution_for(card["case_id"])
        except Exception:
            resolution = None
        if resolution is None:
            unresolved.append(card)
    return unresolved
