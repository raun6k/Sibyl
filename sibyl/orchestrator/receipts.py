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


class LoggingLLM:
    """Writes each Nightshift receipt onto the run log as it happens."""

    def __init__(self, inner: object, log: RunLog | None) -> None:
        self.inner = inner
        self.log = log
        self.receipts: list[dict[str, Any]] = []

    def complete(self, lane: str, messages: list[dict[str, str]], schema: type[Any]) -> Any:
        from sibyl.llm.client import LLMUnavailable

        try:
            done = self.inner.complete(lane, messages, schema)  # type: ignore[attr-defined]
        except LLMUnavailable as exc:
            remember_calls(self.receipts, exc.receipts, schema, self.log)
            raise
        remember_calls(self.receipts, tuple(done.attempts) + (done.receipt,), schema, self.log)
        return done
