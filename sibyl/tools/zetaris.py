"""Read-only Zetaris queries.

Agents may pass SELECT or WITH. Anything else is refused before a request
is sent. The returned statement is what was run, so a run log can store it.
"""

from __future__ import annotations

import json
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sibyl.config import Settings, load_settings


class SqlLog(Protocol):
    def tool(self, actor: str, sql: str, rows: int, ms: float, truncated: bool) -> str: ...


_sql_log: ContextVar[SqlLog | None] = ContextVar("sql_log", default=None)
_sql_receipts: ContextVar[list[dict[str, object]] | None] = ContextVar("sql_receipts", default=None)
_sql_actor: ContextVar[str] = ContextVar("sql_actor", default="orchestrator")


class tracing_sql:
    """Record each `run_sql` on the open run and on `receipts`."""

    def __init__(self, log: SqlLog, receipts: list[dict[str, object]], actor: str = "orchestrator") -> None:
        self._log = log
        self._receipts = receipts
        self._actor = actor
        self._tokens: tuple[object, object, object] | None = None

    def __enter__(self) -> tracing_sql:
        self._tokens = (
            _sql_log.set(self._log),
            _sql_receipts.set(self._receipts),
            _sql_actor.set(self._actor),
        )
        return self

    def __exit__(self, *exc: object) -> None:
        if self._tokens is None:
            return
        log_token, receipt_token, actor_token = self._tokens
        _sql_log.reset(log_token)  # type: ignore[arg-type]
        _sql_receipts.reset(receipt_token)  # type: ignore[arg-type]
        _sql_actor.reset(actor_token)  # type: ignore[arg-type]


class sql_actor:
    """Name the agent that owns the `run_sql` calls in this block."""

    def __init__(self, actor: str) -> None:
        self._actor = actor
        self._token: object = None

    def __enter__(self) -> sql_actor:
        self._token = _sql_actor.set(self._actor)
        return self

    def __exit__(self, *exc: object) -> None:
        _sql_actor.reset(self._token)  # type: ignore[arg-type]


class SqlRejected(PermissionError):
    """The statement is not a single read-only query."""


class ResultTruncated(RuntimeError):
    """The row count reached `limit`, so the page may be cut off.

    A full page is not returned as a normal result. Callers that need every
    row page the query, or raise, instead of treating the cut as complete.
    """


@dataclass(frozen=True)
class SqlResult:
    statement: str
    rows: list[dict[str, str]]
    milliseconds: int
    truncated: bool = False


# Statements the inventory sync may send besides SELECT: the USL model and its
# data-quality rules. Agents never get this path; `run_sql` stays read-only.
ADMIN_PREFIXES = (
    "create namespace",
    "compile usl",
    "activate usl table",
    "update usl",
    "load usl",
    "remove usl",
    "register dq",
    "update dq",
    "run dq",
    "show dq",
    "list dq usl",
    "refresh datasource tables",
    "uncache datasource",
    "register datasource table",
    "offsite cache table",
    "offsite uncache table",
    "explain query",
)


def run_admin(sql: str, *, settings: Settings | None = None, timeout: float = 180, limit: int = 10000) -> SqlResult:
    """Run one allow-listed USL / data-quality / cache statement."""
    # COMPILE USL needs each CREATE TABLE on its own line, so the text is sent as written.
    text = sql.strip()
    lowered = " ".join(text.split()).lower()
    if not lowered.startswith(ADMIN_PREFIXES):
        raise SqlRejected("run_admin only allows USL, data-quality, datasource refresh and cache statements")
    return _post(text, settings=settings, timeout=timeout, limit=limit)


def run_sql(
    sql: str,
    *,
    settings: Settings | None = None,
    timeout: float = 180,
    limit: int = 10000,
) -> SqlResult:
    return _post(readonly_statement(sql), settings=settings, timeout=timeout, limit=limit)


def _post(statement: str, *, settings: Settings | None, timeout: float, limit: int) -> SqlResult:
    active = settings or load_settings()
    missing = [
        name
        for name, value in (
            ("ZETARIS_REST_URL", active.zetaris_rest_url),
            ("ZETARIS_API_KEY", active.zetaris_api_key),
            ("ZETARIS_ORG_ID", active.zetaris_org_id),
        )
        if not value
    ]
    if missing:
        raise RuntimeError("missing " + ", ".join(missing))
    url = active.zetaris_rest_url.rstrip("/") + "/sql-editor/sqls/run"
    payload = {
        "queryId": str(uuid.uuid4()),
        "sql": statement,
        "source": "SqlEditor",
        "limit": limit,
    }
    request = Request(
        url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {active.zetaris_api_key}",
            "X-Org-ID": active.zetaris_org_id,
            "X-Request-ID": str(uuid.uuid4()),
            "Content-Type": "application/json",
        },
    )
    started = time.perf_counter()
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except HTTPError as exc:
        raw = exc.read()
        status = exc.code
    except URLError as exc:
        raise RuntimeError(active.redact(str(exc.reason))) from None
    milliseconds = int((time.perf_counter() - started) * 1000)
    text = raw.decode(errors="replace")
    if status >= 400:
        raise RuntimeError(active.redact(f"HTTP {status} {text[:500]}"))
    try:
        body = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(active.redact(text[:500])) from exc
    if isinstance(body, dict) and body.get("error"):
        raise RuntimeError(active.redact(json.dumps(body["error"])[:500]))
    rows = _rows(body)
    # Reaching the limit is the only signal the REST call gives. An exact
    # full page is treated as cut off so a short page cannot pass for a complete one.
    truncated = len(rows) >= limit
    result = SqlResult(
        statement=statement,
        rows=rows,
        milliseconds=milliseconds,
        truncated=truncated,
    )
    _remember(result)
    return result


def _remember(result: SqlResult) -> None:
    log = _sql_log.get()
    receipts = _sql_receipts.get()
    if log is None and receipts is None:
        return
    payload = {
        "sql": result.statement,
        "rows": len(result.rows),
        "ms": result.milliseconds,
        "truncated": result.truncated,
    }
    actor = _sql_actor.get()
    if log is not None:
        log.tool(actor, result.statement, len(result.rows), float(result.milliseconds), result.truncated)
    if receipts is not None:
        receipts.append(payload)


def readonly_statement(sql: str) -> str:
    """Return the statement if it is one SELECT or WITH, else refuse it."""
    lines: list[str] = []
    for line in sql.splitlines():
        if "--" in line:
            line = line.split("--", 1)[0]
        lines.append(line)
    text = " ".join(lines).strip()
    if text.endswith(";"):
        text = text[:-1].strip()
    if not text or ";" in text:
        raise SqlRejected("run_sql only allows a single SELECT or WITH statement")
    head = text.split(None, 1)[0].lower()
    if head not in {"select", "with"}:
        raise SqlRejected("run_sql only allows SELECT or WITH")
    return text


def _rows(payload: object) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        return []
    headers = payload.get("headers")
    data = payload.get("data")
    if not isinstance(headers, list) or not isinstance(data, list):
        return []
    rows: list[dict[str, str]] = []
    for item in data:
        if isinstance(item, list):
            rows.append(
                {
                    str(headers[index]): "" if value is None else str(value)
                    for index, value in enumerate(item)
                }
            )
    return rows
