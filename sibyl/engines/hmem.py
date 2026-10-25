"""Python client for one long-lived H-MEM process.

The process is the TypeScript module compiled with the `typescript`
already in `engines/`. The store stays on disk under `var/hmem/`.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any

from sibyl.config import ROOT

SERVER = ROOT / "engines" / "hmem" / "build" / "server.js"
TSC = ROOT / "engines" / "node_modules" / "typescript" / "bin" / "tsc"
TSCONFIG = ROOT / "engines" / "hmem" / "tsconfig.json"
SOURCE = ROOT / "engines" / "hmem" / "src"
STORE = ROOT / "var" / "hmem"


def compile_hmem() -> Path:
    """Emit `server.js` when sources are newer than the last build."""
    if not TSC.is_file():
        raise RuntimeError("typescript is not installed in engines/; npm install there, not tsx")
    newest = max(path.stat().st_mtime for path in SOURCE.glob("*.ts"))
    if SERVER.is_file() and SERVER.stat().st_mtime >= newest:
        return SERVER
    subprocess.run([str(TSC), "-p", str(TSCONFIG)], check=True, cwd=ROOT)
    if not SERVER.is_file():
        raise RuntimeError("typescript did not emit the H-MEM server")
    return SERVER


class HmemClient:
    def __init__(self, store: Path | None = None) -> None:
        server = compile_hmem()
        self.store = store or STORE
        self.store.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["HMEM_DIR"] = str(self.store)
        self._proc = subprocess.Popen(
            ["node", str(server)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            cwd=ROOT,
            env=env,
            text=True,
            bufsize=1,
        )
        self._lock = threading.Lock()
        self._next = 0
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._proc.poll() is None:
                self._request("close", {})
        finally:
            if self._proc.poll() is None:
                self._proc.terminate()
                self._proc.wait(timeout=5)

    def __enter__(self) -> HmemClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def trust(self, source: str, field: str = "affected_ranges", ecosystem: str = "*") -> float | None:
        result = self._request("trust", {"source": source, "field": field, "ecosystem": ecosystem})
        if not isinstance(result, dict):
            return None
        weight = result.get("weight")
        return float(weight) if isinstance(weight, (int, float)) else None

    def resolve(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = self._request("resolve", payload)
        if not isinstance(result, dict):
            raise RuntimeError("resolve did not return an object")
        return result

    def approve(self, pending_id: str) -> dict[str, Any]:
        result = self._request("approve", {"id": pending_id})
        if not isinstance(result, dict):
            raise RuntimeError("approve did not return an object")
        return result

    def reject(self, pending_id: str) -> dict[str, Any]:
        result = self._request("reject", {"id": pending_id})
        if not isinstance(result, dict):
            raise RuntimeError("reject did not return an object")
        return result

    def resolution_for(self, case_id: str) -> dict[str, Any] | None:
        result = self._request("resolution_for", {"case_id": case_id})
        if not isinstance(result, dict):
            return None
        found = result.get("resolution")
        return found if isinstance(found, dict) else None

    def mapping_for(self, product: str) -> str | None:
        result = self._request("mapping_for", {"product": product})
        if not isinstance(result, dict):
            return None
        purl = result.get("purl")
        return purl if isinstance(purl, str) and purl else None

    def propose_mapping(self, product: str, purl: str, reason: str = "") -> dict[str, Any]:
        result = self._request("propose_mapping", {"product": product, "purl": purl, "reason": reason})
        if not isinstance(result, dict):
            raise RuntimeError("propose_mapping did not return an object")
        return result

    def summary(self, run_id: str, *, needs_human: int, ranked: int, closed: int) -> None:
        self._request(
            "summary",
            {"run_id": run_id, "needs_human": needs_human, "ranked": ranked, "closed": closed},
        )

    def snapshot(self) -> dict[str, Any]:
        result = self._request("snapshot", {})
        if not isinstance(result, dict):
            raise RuntimeError("snapshot did not return an object")
        return result

    def reset(self) -> None:
        self._request("reset", {})

    def _request(self, method: str, payload: dict[str, Any]) -> Any:
        if self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("hmem process is not running")
        with self._lock:
            self._next += 1
            ident = str(self._next)
            self._proc.stdin.write(json.dumps({"id": ident, "method": method, "payload": payload}) + "\n")
            self._proc.stdin.flush()
            line = self._proc.stdout.readline()
        if line == "":
            raise RuntimeError("hmem process closed")
        message = json.loads(line)
        if message.get("id") != ident:
            raise RuntimeError("hmem reply did not match the request")
        if not message.get("ok"):
            raise RuntimeError(str(message.get("error") or "hmem error"))
        return message.get("result")
