"""Keep one receipt, and one run event, for each Nightshift call."""

from __future__ import annotations

from typing import Any

from sibyl.llm.client import Receipt
from sibyl.orchestrator.log import RunLog

AGENTS = {
    "ExtractedRange": "matcher",
    "QuoteJudgement": "critic",
    "Rationale": "prioritiser",
    "IntentGuess": "scout",
    "ProductMatch": "mapper",
}


def remember_calls(receipts: list[dict[str, Any]], calls: list[Receipt] | tuple[Receipt, ...], schema: type[Any], log: RunLog | None) -> None:
    agent = AGENTS.get(getattr(schema, "__name__", ""), "model")
    for receipt in calls:
        payload = receipt.model_dump()
        payload["agent"] = agent
        receipts.append(payload)
        if log is not None and log.run_id:
            log.llm_call(agent, receipt)
