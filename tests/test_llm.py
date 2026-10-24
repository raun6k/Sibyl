"""Nightshift client against an in-process httpx transport. No network."""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import BaseModel

from sibyl.config import Settings
from sibyl.llm import LLMClient, LLMUnavailable

FAST = "nvidia/fast"
DEEP = "nvidia/deep"
JUDGE = "nvidia/judge"
TOKEN = "test-token-secret"


class Answer(BaseModel):
    answer: str


def _settings(**overrides) -> Settings:
    values = {
        "database_url": "",
        "meterless_base_url": "http://nightshift.test/v1",
        "meterless_runtime_token": TOKEN,
        "meterless_model_fast": FAST,
        "meterless_model_deep": DEEP,
        "meterless_model_judge": JUDGE,
        "run_max_tokens": 400_000,
    }
    values.update(overrides)
    return Settings(**values)


def _body(content: str, requested: str, routed: str | None, *, tokens: int = 12, receipt_id: str = "rcpt-1") -> dict:
    payload = {
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 4, "completion_tokens": tokens - 4, "total_tokens": tokens},
        "meterless": {
            "receipt_id": receipt_id,
            "requested_model": requested,
            "usage": {"tokens": tokens, "latency_ms": 21},
        },
    }
    if routed is not None:
        payload["meterless"]["routed_model"] = routed
    return payload


def _response(content: str, requested: str, routed: str | None, **kwargs) -> httpx.Response:
    return httpx.Response(200, json=_body(content, requested, routed, **kwargs))


def _client(handler, **overrides) -> tuple[LLMClient, httpx.Client]:
    transport = httpx.MockTransport(handler)
    http = httpx.Client(transport=transport)
    return LLMClient(_settings(**overrides), client=http), http


def test_valid_call_records_the_routed_model():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        return _response('{"answer": "yes"}', body["model"], body["model"], receipt_id="rcpt-valid")

    client, http = _client(handler)
    try:
        done = client.complete("fast", [{"role": "user", "content": "Say yes."}], Answer)
    finally:
        client.close()
        http.close()

    assert done.output.answer == "yes"
    assert done.repaired is False
    assert done.fell_back is False
    assert done.lane == "fast"
    assert done.receipt.requested_model == FAST
    assert done.receipt.routed_model == FAST
    assert done.receipt.rerouted is False
    assert done.receipt.receipt_id == "rcpt-valid"
    assert done.receipt.tokens == 12
    assert done.receipt.latency_ms == 21
    assert done.receipt.routed_model == done.receipt.requested_model
    request = seen[0]
    assert request.url.path == "/v1/chat/completions"
    assert request.headers["meterless-app"] == "sibyl"
    assert request.headers["meterless-scope"] == "user"
    assert request.headers["authorization"] == f"Bearer {TOKEN}"
    assert len(seen) == 1


def test_invalid_output_is_repaired_once_on_the_same_lane():
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        if len(seen) == 1:
            return _response("not json", body["model"], body["model"])
        return _response('{"answer": "repaired"}', body["model"], body["model"], receipt_id="rcpt-repair")

    client, http = _client(handler)
    try:
        done = client.complete("deep", [{"role": "user", "content": "Answer."}], Answer)
    finally:
        client.close()
        http.close()

    assert done.output.answer == "repaired"
    assert done.repaired is True
    assert done.fell_back is False
    assert done.lane == "deep"
    assert [body["model"] for body in seen] == [DEEP, DEEP]
    assert seen[1]["messages"][-2]["role"] == "assistant"
    assert seen[1]["messages"][-2]["content"] == "not json"
    assert done.receipt.receipt_id == "rcpt-repair"
    assert done.receipt.routed_model == DEEP


def test_invalid_twice_falls_back_to_the_other_lane():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body["model"])
        if body["model"] == FAST:
            return _response("nope", body["model"], body["model"])
        return _response('{"answer": "from-deep"}', body["model"], body["model"], receipt_id="rcpt-fb")

    client, http = _client(handler)
    try:
        done = client.complete("fast", [{"role": "user", "content": "Answer."}], Answer)
    finally:
        client.close()
        http.close()

    assert seen == [FAST, FAST, DEEP]
    assert done.output.answer == "from-deep"
    assert done.fell_back is True
    assert done.repaired is True
    assert done.lane == "deep"
    assert done.receipt.requested_model == DEEP
    assert done.receipt.routed_model == DEEP
    assert done.receipt.receipt_id == "rcpt-fb"


def test_reroute_is_flagged_and_the_requested_model_is_not_the_one_that_ran():
    routed = "nvidia/nemotron-3.5-super-vl-120b-a12b"

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return _response('{"answer": "ok"}', body["model"], routed, receipt_id="rcpt-route")

    client, http = _client(handler)
    try:
        done = client.complete("fast", [{"role": "user", "content": "Answer."}], Answer)
    finally:
        client.close()
        http.close()

    assert done.receipt.requested_model == FAST
    assert done.receipt.routed_model == routed
    assert done.receipt.rerouted is True
    assert done.receipt.routed_model != done.receipt.requested_model
    reported = f"ran {done.receipt.routed_model}"
    assert FAST not in reported


def test_missing_routed_model_is_not_reported_as_the_requested_model():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        body = json.loads(request.content)
        routed = None if calls == 1 else body["model"]
        return _response('{"answer": "second"}', body["model"], routed, receipt_id="rcpt-2")

    client, http = _client(handler)
    try:
        done = client.complete("judge", [{"role": "user", "content": "Answer."}], Answer)
    finally:
        client.close()
        http.close()

    assert calls == 2
    assert done.receipt.routed_model == JUDGE
    assert done.receipt.rerouted is False
    assert done.fell_back is False


def test_token_budget_stops_the_next_call():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        body = json.loads(request.content)
        return _response('{"answer": "once"}', body["model"], body["model"], tokens=5)

    client, http = _client(handler, run_max_tokens=5)
    try:
        first = client.complete("fast", [{"role": "user", "content": "Answer."}], Answer)
        assert first.output.answer == "once"
        assert client.budget.used == 5
        with pytest.raises(LLMUnavailable) as caught:
            client.complete("fast", [{"role": "user", "content": "Again."}], Answer)
    finally:
        client.close()
        http.close()

    assert calls == 1
    assert caught.value.flagged is True
    assert caught.value.rationale == "unavailable"
    assert caught.value.reason == "token budget exhausted"
    assert TOKEN not in str(caught.value)


def test_http_errors_do_not_leak_the_token(caplog):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500, text=f"refused {TOKEN}")

    client, http = _client(handler)
    try:
        with pytest.raises(LLMUnavailable) as caught:
            client.complete("fast", [{"role": "user", "content": "Answer."}], Answer)
    finally:
        client.close()
        http.close()

    assert calls == 3
    assert caught.value.flagged is True
    assert TOKEN not in str(caught.value)
    assert TOKEN not in repr(caught.value)
    assert TOKEN not in caplog.text
    assert TOKEN not in repr(client.settings)
