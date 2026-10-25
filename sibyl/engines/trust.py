"""Trust weights read from H-MEM, with the data.md table as the fallback.

A run binds one table. When the engine cannot be reached, lookups use
`Settings.trust_weights` and `unavailable` is set so confidence can say so.
"""

from __future__ import annotations

from contextvars import ContextVar, Token

from sibyl.config import DEFAULT_TRUST, Settings
from sibyl.engines.hmem import HmemClient

_bound: ContextVar["TrustTable | None"] = ContextVar("trust_table", default=None)


class TrustTable:
    def __init__(self, client: HmemClient | None, settings: Settings | None = None) -> None:
        self.client = client
        self.settings = settings
        self.unavailable = client is None

    def weight(self, source: str, field: str = "affected_ranges", ecosystem: str = "*") -> float:
        key = source.strip().lower()
        if self.client is None:
            self.unavailable = True
            return _default(key, self.settings)
        try:
            found = self.client.trust(key, field, ecosystem)
        except Exception:
            self.unavailable = True
            return _default(key, self.settings)
        if found is None:
            return _default(key, self.settings)
        return found

    def bind(self) -> Token["TrustTable | None"]:
        return _bound.set(self)


def current_table() -> TrustTable | None:
    return _bound.get()


def reset_table(token: Token["TrustTable | None"]) -> None:
    _bound.reset(token)


def _default(source: str, settings: Settings | None) -> float:
    table = settings.trust_weights if settings is not None else DEFAULT_TRUST
    if source in table:
        return table[source]
    return table.get("llm-extracted", DEFAULT_TRUST["llm-extracted"])
