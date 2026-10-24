"""Read-only Zetaris queries.

Agents may pass SELECT or WITH. Anything else is refused before a request
is sent. The returned statement is what was run, so a run log can store it.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sibyl.config import Settings, load_settings


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


def run_sql(
    sql: str,
    *,
    settings: Settings | None = None,
    timeout: float = 180,
    limit: int = 10000,
) -> SqlResult:
    statement = readonly_statement(sql)
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
    return SqlResult(
        statement=statement,
        rows=rows,
        milliseconds=milliseconds,
        truncated=truncated,
    )


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
