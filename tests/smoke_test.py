"""Sponsor connection check. Prints three lines, each PASS or FAIL.

Reads configuration only from the repo `.env`. Does not print secrets.
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"

# Getting-started verification query. Pikachu has two abilities, so this
# returns 2 rows once 02_pokeapi_create.sql has registered the view.
PIKACHU_SQL = "SELECT ability_name, is_hidden FROM pokeapi.pikachu_abilities_table"


def load_env(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def need(env: dict[str, str], *names: str) -> str | None:
    missing = [name for name in names if not env.get(name)]
    if missing:
        return "missing " + ", ".join(missing)
    return None


def shorten(text: str, limit: int = 180) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "..."


def request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict | None = None,
    timeout: float = 20,
) -> tuple[int, bytes]:
    data = json.dumps(body).encode() if body is not None else None
    req = Request(url, data=data, method=method, headers=headers or {})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except HTTPError as exc:
        return exc.code, exc.read()


def zetaris_web(env: dict[str, str]) -> str:
    missing = need(env, "ZETARIS_REST_URL", "ZETARIS_API_KEY", "ZETARIS_ORG_ID")
    if missing:
        return f"FAIL Zetaris web: {missing}"
    url = env["ZETARIS_REST_URL"].rstrip("/") + "/datasource/datasources"
    headers = {
        "Authorization": f"Bearer {env['ZETARIS_API_KEY']}",
        "X-Org-ID": env["ZETARIS_ORG_ID"],
        "X-Request-ID": str(uuid.uuid4()),
    }
    try:
        status, raw = request(url, headers=headers, timeout=10)
    except URLError as exc:
        return f"FAIL Zetaris web: {shorten(str(exc.reason))}"
    except OSError as exc:
        return f"FAIL Zetaris web: {shorten(str(exc))}"
    if status >= 400:
        return f"FAIL Zetaris web: HTTP {status} {shorten(raw.decode(errors='replace'))}"
    return f"PASS Zetaris web: HTTP {status}"


def zetaris_sql(env: dict[str, str]) -> str:
    missing = need(env, "ZETARIS_REST_URL", "ZETARIS_API_KEY", "ZETARIS_ORG_ID")
    if missing:
        return f"FAIL Zetaris SQL: {missing}"
    url = env["ZETARIS_REST_URL"].rstrip("/") + "/sql-editor/sqls/run"
    headers = {
        "Authorization": f"Bearer {env['ZETARIS_API_KEY']}",
        "X-Org-ID": env["ZETARIS_ORG_ID"],
        "X-Request-ID": str(uuid.uuid4()),
        "Content-Type": "application/json",
    }
    body = {
        "queryId": str(uuid.uuid4()),
        "sql": PIKACHU_SQL,
        "source": "SqlEditor",
        "limit": 20,
    }
    try:
        status, raw = request(url, method="POST", headers=headers, body=body, timeout=60)
    except URLError as exc:
        return f"FAIL Zetaris SQL: {shorten(str(exc.reason))}"
    except OSError as exc:
        return f"FAIL Zetaris SQL: {shorten(str(exc))}"
    if status >= 400:
        return f"FAIL Zetaris SQL: HTTP {status} {shorten(raw.decode(errors='replace'))}"
    try:
        payload = json.loads(raw.decode())
    except json.JSONDecodeError:
        return "FAIL Zetaris SQL: response was not JSON"
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return "FAIL Zetaris SQL: response had no row list"
    if len(rows) != 2:
        return f"FAIL Zetaris SQL: expected 2 rows, got {len(rows)}"
    return "PASS Zetaris SQL: 2 rows"


def nightshift(env: dict[str, str]) -> str:
    missing = need(env, "METERLESS_BASE_URL", "METERLESS_RUNTIME_TOKEN", "METERLESS_MODEL_FAST")
    if missing:
        return f"FAIL Nemotron: {missing}"
    requested = env["METERLESS_MODEL_FAST"]
    url = env["METERLESS_BASE_URL"].rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {env['METERLESS_RUNTIME_TOKEN']}",
        "Content-Type": "application/json",
        "meterless-app": "sibyl",
        "meterless-scope": "user",
    }
    body = {
        "model": requested,
        "messages": [{"role": "user", "content": "Reply with the single word ok."}],
        "max_tokens": 16,
    }
    try:
        status, raw = request(url, method="POST", headers=headers, body=body, timeout=90)
    except URLError as exc:
        return f"FAIL Nemotron: {shorten(str(exc.reason))}"
    except OSError as exc:
        return f"FAIL Nemotron: {shorten(str(exc))}"
    if status >= 400:
        return f"FAIL Nemotron: HTTP {status} {shorten(raw.decode(errors='replace'))}"
    try:
        payload = json.loads(raw.decode())
    except json.JSONDecodeError:
        return "FAIL Nemotron: response was not JSON"
    try:
        text = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return "FAIL Nemotron: response had no message text"
    if not isinstance(text, str) or not text.strip():
        return "FAIL Nemotron: response text was empty"
    meterless = payload.get("meterless") if isinstance(payload, dict) else None
    actual = meterless.get("routed_model") if isinstance(meterless, dict) else None
    if not actual:
        return "FAIL Nemotron: response had no meterless.routed_model"
    rerouted = " rerouted" if actual != requested else ""
    return f"PASS Nemotron: requested {requested} actual {actual}{rerouted}"


def main() -> int:
    env = load_env(ENV_PATH)
    lines = [zetaris_web(env), zetaris_sql(env), nightshift(env)]
    print("\n".join(lines))
    return 0 if all(line.startswith("PASS") for line in lines) else 1


if __name__ == "__main__":
    sys.exit(main())
