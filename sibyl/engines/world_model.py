"""Python client for one long-lived World Model process.

The process is the TypeScript module compiled with the `typescript`
already in `engines/`. It speaks JSON lines on stdin and stdout.
"""

from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from sibyl.config import ROOT
from sibyl.engines.messages import (
    AliasLink,
    Claim,
    Conflict,
    CriticDecision,
    Diff,
    DraftVerdict,
    Escalation,
    Priority,
    RecheckRequest,
    SourceMap,
    Verdict,
)

SERVER = ROOT / "engines" / "world-model" / "build" / "server.js"
TSC = ROOT / "engines" / "node_modules" / "typescript" / "bin" / "tsc"
TSCONFIG = ROOT / "engines" / "tsconfig.build.json"
SOURCE = ROOT / "engines" / "world-model" / "src"


def compile_world_model() -> Path:
    """Emit `server.js` when sources are newer than the last build."""
    if not TSC.is_file():
        raise RuntimeError("typescript is not installed in engines/; npm install there, not tsx")
    newest = max(path.stat().st_mtime for path in SOURCE.glob("*.ts"))
    if SERVER.is_file() and SERVER.stat().st_mtime >= newest:
        return SERVER
    subprocess.run([str(TSC), "-p", str(TSCONFIG)], check=True, cwd=ROOT / "engines")
    if not SERVER.is_file():
        raise RuntimeError("typescript did not emit the world model server")
    return SERVER


class WorldModelClient:
    def __init__(self) -> None:
        server = compile_world_model()
        self._proc = subprocess.Popen(
            ["node", str(server)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
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

    def __enter__(self) -> WorldModelClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def claim(self, message: Claim) -> Diff:
        return self._apply("claim", message)

    def alias_link(self, message: AliasLink) -> Diff:
        return self._apply("alias_link", message)

    def source_map(self, message: SourceMap) -> Diff:
        return self._apply("source_map", message)

    def draft_verdict(self, message: DraftVerdict) -> Diff:
        return self._apply("draft_verdict", message)

    def conflict(self, message: Conflict) -> Diff:
        return self._apply("conflict", message)

    def recheck_request(self, message: RecheckRequest) -> Diff:
        return self._apply("recheck_request", message)

    def critic_decision(self, message: CriticDecision) -> Diff:
        return self._apply("critic_decision", message)

    def verdict(self, message: Verdict) -> Diff:
        return self._apply("verdict", message)

    def priority(self, message: Priority) -> Diff:
        return self._apply("priority", message)

    def escalation(self, message: Escalation) -> Diff:
        return self._apply("escalation", message)

    def case(self, case_id: str) -> dict[str, Any]:
        result = self._request("case", {"case_id": case_id})
        if not isinstance(result, dict):
            raise RuntimeError("case projection was not an object")
        return result

    def _apply(self, method: str, message: BaseModel) -> Diff:
        result = self._request(method, message.model_dump(by_alias=True))
        return Diff.model_validate(result)

    def _request(self, method: str, payload: dict[str, Any]) -> Any:
        if self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("world model process is not running")
        with self._lock:
            self._next += 1
            ident = str(self._next)
            self._proc.stdin.write(json.dumps({"id": ident, "method": method, "payload": payload}) + "\n")
            self._proc.stdin.flush()
            line = self._proc.stdout.readline()
        if line == "":
            raise RuntimeError("world model process closed")
        message = json.loads(line)
        if message.get("id") != ident:
            raise RuntimeError("world model reply did not match the request")
        if not message.get("ok"):
            raise RuntimeError(str(message.get("error") or "world model error"))
        return message.get("result")
