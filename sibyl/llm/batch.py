"""Nightshift batch jobs, for work where any Nemotron lane is fine.

`POST /v1/jobs` with `kind: batch` takes many independent requests in one
job. Status is `GET /v1/jobs/{id}`; each answer is
`GET /v1/jobs/{id}/attempts/{seq}`, where `slot` is the request's position
(1-based). Batch spreads requests over the fleet's lanes round-robin and
cannot pin one, and attempts carry no receipt id, so Sibyl uses it only for
model rationales. A job that does not finish within the wait (a quiet
window that has not opened, an error, a timeout) is cancelled and the
caller falls back to chat completions.

Checked live on the M1–M4 edition (2026-10-26): `window: "quiet"` is
accepted and answered with an `estimated_start` in the quiet window, but
the job record then reads `window: "now"` and starts at once.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
from pydantic import BaseModel, ValidationError

from sibyl.config import Settings, load_settings
from sibyl.llm.client import Receipt, _parse_json, _with_schema

_DONE = {"completed", "failed", "cancelled", "canceled", "error"}


@dataclass
class BatchResult:
    job_id: str = ""
    status: str = ""
    window_requested: str = ""
    window_ran: str = ""
    estimated_start: str = ""
    # One parsed output per request, None where the attempt was missing or did not parse.
    outputs: list[Any] = field(default_factory=list)
    receipts: list[Receipt] = field(default_factory=list)
    error: str = ""
    seconds: float = 0

    def summary(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "window_requested": self.window_requested,
            "window_ran": self.window_ran,
            "estimated_start": self.estimated_start,
            "answered": sum(1 for item in self.outputs if item is not None),
            "requests": len(self.outputs),
            "error": self.error,
            "seconds": round(self.seconds, 1),
        }


class NightshiftBatch:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        client: httpx.Client | None = None,
        wait_seconds: float = 180,
        poll_seconds: float = 2,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings or load_settings()
        self._client = client or httpx.Client(timeout=30)
        self._owns = client is None
        self.wait_seconds = wait_seconds
        self.poll_seconds = poll_seconds
        self._sleep = sleep

    def close(self) -> None:
        if self._owns:
            self._client.close()

    def run(self, requests: list[list[dict[str, str]]], schema: type[BaseModel], *, window: str = "now", lane: str = "fast") -> BatchResult:
        """Send every request as one batch job and wait for it. Never raises for a job failure."""
        result = BatchResult(window_requested=window, outputs=[None] * len(requests))
        if not requests:
            result.status = "empty"
            return result
        started = time.perf_counter()
        model = self.settings.meterless_model_fast if lane == "fast" else self.settings.meterless_model_deep
        body = {
            "kind": "batch",
            "window": window,
            "requests": [{"messages": _with_schema(messages, schema), "model": model} for messages in requests],
        }
        try:
            created = self._post("/jobs", body)
            result.job_id = str(created.get("id") or "")
            result.estimated_start = str(created.get("estimated_start") or "")
            if not result.job_id:
                raise RuntimeError("the job had no id")
            record = self._wait(result.job_id)
            result.status = str(record.get("status") or "")
            result.window_ran = str(record.get("window") or "")
            if result.status != "completed":
                if result.status not in _DONE:
                    self._cancel(result.job_id)
                    result.error = f"not finished after {self.wait_seconds:.0f} s (status {result.status or 'unknown'})"
                else:
                    result.error = f"job {result.status}"
            generated = int(record.get("generated") or 0)
            for seq in range(1, generated + 1):
                attempt = self._get(f"/jobs/{result.job_id}/attempts/{seq}")
                slot = int(attempt.get("slot") or seq) - 1
                if not 0 <= slot < len(requests):
                    continue
                result.receipts.append(_attempt_receipt(attempt, model, result.job_id))
                try:
                    result.outputs[slot] = schema.model_validate(_parse_json(str(attempt.get("text") or "")))
                except (ValueError, ValidationError, json.JSONDecodeError):
                    result.outputs[slot] = None
        except (httpx.HTTPError, RuntimeError, ValueError) as exc:
            result.error = self.settings.redact(str(exc))[:300]
            result.status = result.status or "error"
        result.seconds = time.perf_counter() - started
        return result

    def _wait(self, job_id: str) -> dict[str, Any]:
        deadline = time.perf_counter() + self.wait_seconds
        record: dict[str, Any] = {}
        while True:
            record = self._get(f"/jobs/{job_id}")
            if str(record.get("status") or "") in _DONE or time.perf_counter() >= deadline:
                return record
            self._sleep(self.poll_seconds)

    def _cancel(self, job_id: str) -> None:
        try:
            self._client.post(f"{self._base()}/jobs/{job_id}/cancel", headers=self._headers())
        except httpx.HTTPError:
            pass

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        response = self._client.post(f"{self._base()}{path}", json=body, headers=self._headers())
        if response.status_code >= 400:
            raise RuntimeError(f"POST {path} answered {response.status_code}: {response.text[:200]}")
        return response.json()

    def _get(self, path: str) -> dict[str, Any]:
        response = self._client.get(f"{self._base()}{path}", headers=self._headers())
        if response.status_code >= 400:
            raise RuntimeError(f"GET {path} answered {response.status_code}: {response.text[:200]}")
        return response.json()

    def _base(self) -> str:
        return self.settings.meterless_base_url.rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.settings.meterless_runtime_token}"}


def _attempt_receipt(attempt: dict[str, Any], requested: str, job_id: str) -> Receipt:
    """Batch attempts have no receipt id; the job and attempt sequence stand in for it."""
    model = attempt.get("model") if isinstance(attempt.get("model"), dict) else {}
    routed = str(model.get("resolved") or model.get("requested") or "unknown")
    return Receipt(
        lane=str(attempt.get("lane") or "batch"),
        requested_model=requested,
        routed_model=routed,
        receipt_id=f"{job_id}#{attempt.get('seq')}",
        tokens=int(attempt.get("tokens") or 0),
        latency_ms=float(attempt.get("elapsed_ms") or 0),
        rerouted=False,
        mode="batch",
        mode_honoured=model.get("honored") if isinstance(model.get("honored"), bool) else None,
        job_lane=str(attempt.get("lane") or ""),
    )
