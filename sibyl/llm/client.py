"""OpenAI-compatible client for Meterless Nightshift.

`complete` asks one lane for a pydantic object. Invalid output is repaired
once on that lane, then tried once on the fallback lane. HTTP 502
`empty_response`, HTTP 500, and HTTP 499 `request_aborted` take the same
path: one retry, then the fallback lane, then a typed failure. The receipt
always names the model Nightshift actually ran (`meterless.routed_model`).
The requested model is kept beside it and is never treated as the model
that ran. A failed call records its error code and leaves `routed_model`
empty.

Lanes request Nightshift routing modes (`meterless/fast`, `meterless/deep`,
`meterless/fusion`), not model ids. Nothing runs on-device. The Sibyl fleet's
lanes decide which model serves a mode. Nightshift may still answer a mode
on `auto`; the receipt's `mode` is what it ran, and `mode_honoured` says
whether that was the mode we asked for.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from sibyl.config import Settings, load_settings

ModelT = TypeVar("ModelT", bound=BaseModel)

LANES = ("fast", "deep", "critic", "judge")
FALLBACK = {"fast": "deep", "deep": "fast", "critic": "deep", "judge": "deep"}
_MODE_PREFIX = "meterless/"
DEFAULT_TIMEOUT_SECONDS = 150.0
MAX_IN_FLIGHT = 4
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


class Receipt(BaseModel):
    """One Nightshift call. `routed_model` is the model that ran."""

    lane: str
    requested_model: str
    routed_model: str
    receipt_id: str
    tokens: int
    latency_ms: float
    rerouted: bool
    error_code: str = ""
    reasoning_tokens: int | None = None
    # What Nightshift says it ran: `meterless.mode`, its own lane, and how many routes raced.
    mode: str = ""
    mode_honoured: bool | None = None
    job_lane: str = ""
    consensus: str = ""
    raced: int | None = None
    # Where the prompt went (`meterless.egress`): destination and prompt characters sent.
    egress_destination: str = ""
    egress_chars: int | None = None


@dataclass(frozen=True)
class Completion(Generic[ModelT]):
    output: ModelT
    receipt: Receipt
    repaired: bool
    fell_back: bool
    lane: str
    attempts: tuple[Receipt, ...] = ()


class LLMUnavailable(Exception):
    """The lane and its fallback both failed.

    Callers keep the deterministic result, set the rationale to
    "unavailable", and flag the case. `receipts` holds any calls that
    did return a Nightshift receipt.
    """

    def __init__(self, reason: str, receipts: list[Receipt] | None = None):
        super().__init__(reason)
        self.reason = reason
        self.receipts = list(receipts or [])
        self.rationale = "unavailable"
        self.flagged = True


class TokenBudget:
    """Counts completion tokens against `RUN_MAX_TOKENS`.

    A non-positive limit does not cap the run. A call is refused once
    `used` has reached a positive limit. The call that crosses the limit
    is counted; the next one is not sent.
    """

    def __init__(self, limit: int):
        self.limit = limit
        self.used = 0
        self._lock = threading.Lock()

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return self.limit > 0 and self.used >= self.limit

    def add(self, tokens: int) -> None:
        if tokens > 0:
            with self._lock:
                self.used += tokens


@dataclass
class _CallFailed(Exception):
    reason: str
    receipts: list[Receipt] = field(default_factory=list)
    invalid_output: bool = False
    raw: str | None = None
    budget: bool = False
    missing_model: bool = False
    retryable: bool = False


class LLMClient:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        client: httpx.Client | None = None,
        budget: TokenBudget | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.settings = settings or load_settings()
        self.budget = budget or TokenBudget(self.settings.run_max_tokens)
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout)
        self._in_flight = threading.BoundedSemaphore(MAX_IN_FLIGHT)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> LLMClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def model_for(self, lane: str) -> str:
        names = {
            "fast": self.settings.meterless_model_fast,
            "deep": self.settings.meterless_model_deep,
            "critic": self.settings.meterless_model_critic,
            "judge": self.settings.meterless_model_judge,
        }
        if lane not in names:
            raise ValueError(f"unknown lane {lane!r}")
        return names[lane]

    def complete(
        self,
        lane: str,
        messages: list[dict[str, str]],
        schema: type[ModelT],
    ) -> Completion[ModelT]:
        """Return `schema` parsed from the lane, or raise `LLMUnavailable`."""
        if lane not in FALLBACK:
            raise ValueError(f"unknown lane {lane!r}")
        prepared = _with_schema(messages, schema)
        receipts: list[Receipt] = []
        attempts: list[str] = []
        repaired = False

        try:
            output, receipt = self._attempt(lane, prepared, schema)
            return Completion(
                output=output,
                receipt=receipt,
                repaired=False,
                fell_back=False,
                lane=lane,
                attempts=tuple(receipts),
            )
        except _CallFailed as first:
            receipts.extend(first.receipts)
            attempts.append(f"{lane}: {first.reason}")
            if first.budget or self.budget.exhausted:
                raise LLMUnavailable("token budget exhausted", receipts) from None
            repaired = first.invalid_output
            if _retry_same_lane(first):
                retry_messages = prepared
                if first.invalid_output:
                    retry_messages = _repair(prepared, first.raw or "", first.reason)
                try:
                    output, receipt = self._attempt(lane, retry_messages, schema)
                    return Completion(
                        output=output,
                        receipt=receipt,
                        repaired=repaired,
                        fell_back=False,
                        lane=lane,
                        attempts=tuple(receipts),
                    )
                except _CallFailed as second:
                    receipts.extend(second.receipts)
                    attempts.append(f"{lane}: {second.reason}")
                    if second.budget or self.budget.exhausted:
                        raise LLMUnavailable("token budget exhausted", receipts) from None

        fallback = FALLBACK[lane]
        try:
            output, receipt = self._attempt(fallback, prepared, schema)
        except _CallFailed as failed:
            receipts.extend(failed.receipts)
            attempts.append(f"{fallback}: {failed.reason}")
            if failed.budget or self.budget.exhausted:
                reason = "token budget exhausted"
            else:
                reason = f"{lane} failed and fallback {fallback} failed ({'; '.join(attempts)})"
            raise LLMUnavailable(self.settings.redact(reason), receipts) from None
        return Completion(
            output=output,
            receipt=receipt,
            repaired=repaired,
            fell_back=True,
            lane=fallback,
            attempts=tuple(receipts),
        )

    def _attempt(
        self,
        lane: str,
        messages: list[dict[str, str]],
        schema: type[ModelT],
    ) -> tuple[ModelT, Receipt]:
        if self.budget.exhausted:
            raise _CallFailed("token budget exhausted", budget=True)
        model = self.model_for(lane)
        if not model:
            raise _CallFailed(f"missing model for {lane}", missing_model=True)
        payload, receipt = self._post(lane, model, messages)
        try:
            output = schema.model_validate(_parse_json(_content(payload)))
        except (ValueError, ValidationError, json.JSONDecodeError) as exc:
            raw = _content_or_blank(payload)
            raise _CallFailed(str(exc), receipts=[receipt], invalid_output=True, raw=raw) from None
        return output, receipt

    def _post(self, lane: str, model: str, messages: list[dict[str, str]]) -> tuple[dict[str, Any], Receipt]:
        url = self.settings.meterless_base_url.rstrip("/") + "/chat/completions"
        body = {
            "model": model,
            "messages": messages,
            "max_tokens": self.settings.meterless_max_tokens_for(lane),
            "temperature": 0,
        }
        started = time.perf_counter()
        self._in_flight.acquire()
        try:
            try:
                response = self._client.post(url, headers=self._headers(), json=body)
            except httpx.HTTPError as exc:
                raise _CallFailed(self.settings.redact(f"{type(exc).__name__}: {exc}")) from None
        finally:
            self._in_flight.release()
        elapsed_ms = (time.perf_counter() - started) * 1000
        if response.status_code >= 400:
            detail = self.settings.redact(" ".join(response.text.split())[:180])
            code, retryable = _http_error(response.status_code, response.text)
            receipt = _error_receipt(lane, model, elapsed_ms, code)
            raise _CallFailed(
                f"HTTP {response.status_code} {code} {detail}",
                receipts=[receipt],
                retryable=retryable,
            )
        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            raise _CallFailed("response was not JSON") from exc
        if not isinstance(payload, dict):
            raise _CallFailed("response was not a JSON object")
        try:
            receipt = _receipt(lane, model, payload, elapsed_ms)
        except ValueError as exc:
            meterless = payload.get("meterless") if isinstance(payload.get("meterless"), dict) else {}
            usage = meterless.get("usage") if isinstance(meterless.get("usage"), dict) else {}
            self.budget.add(_tokens(payload, usage))
            raise _CallFailed(str(exc)) from None
        self.budget.add(receipt.tokens)
        return payload, receipt

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.settings.meterless_runtime_token}",
            "Content-Type": "application/json",
            "meterless-app": "sibyl",
            "meterless-scope": "user",
        }


def bounded_map(function: Callable[[Any], Any], items: Sequence[Any]) -> list[Any]:
    """Run `function` over `items`, with at most `MAX_IN_FLIGHT` calls at once."""
    batch = list(items)
    if len(batch) <= 1:
        return [function(item) for item in batch]
    with ThreadPoolExecutor(max_workers=MAX_IN_FLIGHT) as pool:
        return list(pool.map(function, batch))


def _retry_same_lane(failed: _CallFailed) -> bool:
    """One more try on the same lane: a repair, or a provider failure.

    A missing model is not retried. The token budget is not retried.
    HTTP 502 `empty_response`, HTTP 500, and HTTP 499 `request_aborted`
    are the provider failures. Other call failures take the same one
    retry so a missing routed model is not reported as the requested one.
    """
    if failed.budget or failed.missing_model:
        return False
    return True


def _http_error(status: int, body: str) -> tuple[str, bool]:
    """Error code and whether this provider failure is retried once."""
    text = body.lower()
    if status == 502 and "empty_response" in text:
        return "empty_response", True
    if status == 500:
        return "500", True
    if status == 499 and "request_aborted" in text:
        return "request_aborted", True
    return str(status), False


def _error_receipt(lane: str, requested: str, elapsed_ms: float, error_code: str) -> Receipt:
    return Receipt(
        lane=lane,
        requested_model=requested,
        routed_model="",
        receipt_id="",
        tokens=0,
        latency_ms=elapsed_ms,
        rerouted=False,
        error_code=error_code,
    )


def _with_schema(messages: list[dict[str, str]], schema: type[BaseModel]) -> list[dict[str, str]]:
    instruction = (
        "Return one JSON object and nothing else. "
        "The object must match this JSON schema: "
        + json.dumps(schema.model_json_schema())
    )
    return [{"role": "system", "content": instruction}, *messages]


def _repair(messages: list[dict[str, str]], raw: str, reason: str) -> list[dict[str, str]]:
    detail = reason if len(reason) <= 400 else reason[:400]
    return [
        *messages,
        {"role": "assistant", "content": raw},
        {
            "role": "user",
            "content": f"Invalid output: {detail}. Return one JSON object matching the schema.",
        },
    ]


def _content(payload: dict[str, Any]) -> str:
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("response had no message text") from exc
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        content = "".join(parts)
    if not isinstance(content, str) or not content.strip():
        raise ValueError("response text was empty")
    return content


def _content_or_blank(payload: dict[str, Any]) -> str:
    try:
        return _content(payload)
    except ValueError:
        return ""


def _parse_json(content: str) -> Any:
    text = content.strip()
    if text.startswith("```"):
        text = _FENCE.sub("", text).strip()
    return json.loads(text)


def _receipt(lane: str, requested: str, payload: dict[str, Any], elapsed_ms: float) -> Receipt:
    meterless = payload.get("meterless")
    if not isinstance(meterless, dict):
        raise ValueError("response had no meterless receipt")
    routed = meterless.get("routed_model")
    if not isinstance(routed, str) or not routed.strip():
        raise ValueError("response had no meterless.routed_model")
    routed = routed.strip()
    receipt_id = meterless.get("receipt_id")
    usage = meterless.get("usage") if isinstance(meterless.get("usage"), dict) else {}
    latency = usage.get("latency_ms")
    if not isinstance(latency, (int, float)):
        latency = elapsed_ms
    mode = meterless.get("mode") if isinstance(meterless.get("mode"), str) else ""
    honoured = _mode_honoured(requested, mode, meterless.get("provider_model"))
    job = meterless.get("job") if isinstance(meterless.get("job"), dict) else {}
    consensus = meterless.get("consensus") if isinstance(meterless.get("consensus"), dict) else {}
    egress = meterless.get("egress") if isinstance(meterless.get("egress"), dict) else {}
    sent = egress.get("sent") if isinstance(egress.get("sent"), dict) else {}
    raced = consensus.get("raced")
    chars = sent.get("prompt_chars")
    return Receipt(
        lane=lane,
        requested_model=requested,
        routed_model=routed,
        receipt_id=str(receipt_id or ""),
        tokens=_tokens(payload, usage),
        latency_ms=float(latency),
        rerouted=(not honoured) if honoured is not None else requested != routed,
        reasoning_tokens=_reasoning_tokens(payload, usage),
        mode=mode,
        mode_honoured=honoured,
        job_lane=str(job.get("lane") or ""),
        consensus=str(consensus.get("level") or ""),
        raced=raced if isinstance(raced, int) else None,
        egress_destination=str(egress.get("destination") or ""),
        egress_chars=chars if isinstance(chars, int) else None,
    )


def _mode_honoured(requested: str, mode: str, provider_model: object) -> bool | None:
    """For a routing-mode request: did Nightshift run that mode? `None` for a model-id request."""
    if not requested.startswith(_MODE_PREFIX):
        return None
    wanted = requested[len(_MODE_PREFIX):]
    if mode:
        return mode == wanted
    if isinstance(provider_model, str) and provider_model:
        return provider_model == requested
    return None


def _reasoning_tokens(payload: dict[str, Any], usage: dict[str, Any]) -> int | None:
    """The reasoning-token figure, when the meterless receipt or OpenAI usage has one."""
    found: list[Any] = []
    if isinstance(usage, dict):
        found.append(usage.get("reasoning_tokens"))
        found.append(usage.get("reasoningTokens"))
        nested = usage.get("tokens")
        if isinstance(nested, dict):
            found.append(nested.get("reasoning"))
            found.append(nested.get("reasoning_tokens"))
            found.append(nested.get("reasoningTokens"))
    meterless = payload.get("meterless")
    if isinstance(meterless, dict):
        found.append(meterless.get("reasoning_tokens"))
        found.append(meterless.get("reasoningTokens"))
    openai_usage = payload.get("usage")
    if isinstance(openai_usage, dict):
        found.append(openai_usage.get("reasoning_tokens"))
        details = openai_usage.get("completion_tokens_details")
        if isinstance(details, dict):
            found.append(details.get("reasoning_tokens"))
    for value in found:
        if isinstance(value, int):
            return value
    return None


def _tokens(payload: dict[str, Any], usage: dict[str, Any]) -> int:
    direct = usage.get("tokens")
    if isinstance(direct, int):
        return direct
    if isinstance(direct, dict):
        total = direct.get("total")
        if isinstance(total, int):
            return total
        incoming = direct.get("input") or direct.get("tokensIn") or 0
        outgoing = direct.get("output") or direct.get("tokensOut") or 0
        if isinstance(incoming, int) and isinstance(outgoing, int):
            return incoming + outgoing
    incoming = usage.get("tokens_in") or usage.get("tokensIn")
    outgoing = usage.get("tokens_out") or usage.get("tokensOut")
    if isinstance(incoming, int) and isinstance(outgoing, int):
        return incoming + outgoing
    openai_usage = payload.get("usage")
    if isinstance(openai_usage, dict) and isinstance(openai_usage.get("total_tokens"), int):
        return openai_usage["total_tokens"]
    return 0
