"""Small Zetaris REST helper for setup and checks.

Sends one Lightning SQL statement per call. Never prints the API key.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent


def load_env(path: Path | None = None) -> dict[str, str]:
    env_path = path or (ROOT / ".env")
    if not env_path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def redact(text: str, *secrets: str) -> str:
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "***")
    return redacted


def split_sql(text: str) -> list[str]:
    """Split a script on semicolons. Strips `--` comments. Keeps quoted text."""
    lines: list[str] = []
    for line in text.splitlines():
        out: list[str] = []
        in_single = False
        in_double = False
        index = 0
        while index < len(line):
            char = line[index]
            if char == "'" and not in_double:
                in_single = not in_single
            elif char == '"' and not in_single:
                in_double = not in_double
            elif char == "-" and not in_single and not in_double and line[index : index + 2] == "--":
                break
            out.append(char)
            index += 1
        lines.append("".join(out))
    body = "\n".join(lines)
    parts: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    for char in body:
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        if char == ";" and not in_single and not in_double:
            statement = "".join(buf).strip()
            if statement:
                parts.append(statement)
            buf = []
        else:
            buf.append(char)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def run_sql(env: dict[str, str], sql: str, *, timeout: float = 90, limit: int = 1000) -> dict:
    """Run one statement. Returns status, milliseconds, payload, and error text."""
    missing = [name for name in ("ZETARIS_REST_URL", "ZETARIS_API_KEY", "ZETARIS_ORG_ID") if not env.get(name)]
    if missing:
        return {
            "status": 0,
            "ms": 0,
            "payload": None,
            "error": "missing " + ", ".join(missing),
        }
    url = env["ZETARIS_REST_URL"].rstrip("/") + "/sql-editor/sqls/run"
    headers = {
        "Authorization": f"Bearer {env['ZETARIS_API_KEY']}",
        "X-Org-ID": env["ZETARIS_ORG_ID"],
        "X-Request-ID": str(uuid.uuid4()),
        "Content-Type": "application/json",
    }
    body = {
        "queryId": str(uuid.uuid4()),
        "sql": sql,
        "source": "SqlEditor",
        "limit": limit,
    }
    started = time.perf_counter()
    try:
        request = Request(url, data=json.dumps(body).encode(), method="POST", headers=headers)
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except HTTPError as exc:
        raw = exc.read()
        status = exc.code
    except URLError as exc:
        ms = int((time.perf_counter() - started) * 1000)
        return {"status": 0, "ms": ms, "payload": None, "error": str(exc.reason)}
    except OSError as exc:
        ms = int((time.perf_counter() - started) * 1000)
        return {"status": 0, "ms": ms, "payload": None, "error": str(exc)}
    ms = int((time.perf_counter() - started) * 1000)
    text = raw.decode(errors="replace")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {"status": status, "ms": ms, "payload": None, "error": text}
    if status >= 400:
        return {"status": status, "ms": ms, "payload": payload, "error": text}
    if isinstance(payload, dict) and payload.get("error"):
        return {"status": status, "ms": ms, "payload": payload, "error": json.dumps(payload["error"])}
    return {"status": status, "ms": ms, "payload": payload, "error": None}


def rows_of(payload: dict | None) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        return []
    headers = payload.get("headers")
    data = payload.get("data")
    if not isinstance(headers, list) or not isinstance(data, list):
        return []
    rows: list[dict[str, str]] = []
    for item in data:
        if isinstance(item, list):
            rows.append({str(headers[i]): "" if value is None else str(value) for i, value in enumerate(item)})
    return rows
