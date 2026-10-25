"""Each Nightshift call becomes one run event, from the receipt recorder."""

from pydantic import BaseModel

from sibyl.config import load_settings
from sibyl.llm import Completion, Receipt
from sibyl.llm.client import LLMUnavailable
from sibyl.orchestrator.log import RunLog

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_demo import RecordingLLM  # noqa: E402


class Answer(BaseModel):
    answer: str


class _Inner:
    def __init__(self, result):
        self.result = result

    def complete(self, lane, messages, schema):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _receipt(**extra) -> Receipt:
    values = dict(
        lane="fast",
        requested_model="requested-model",
        routed_model="routed-model",
        receipt_id="rcpt-1",
        tokens=11,
        latency_ms=42.5,
        rerouted=False,
    )
    values.update(extra)
    return Receipt(**values)


def test_a_nightshift_call_is_written_to_the_run_log():
    done = Completion(
        output=Answer(answer="yes"),
        receipt=_receipt(),
        repaired=False,
        fell_back=False,
        lane="fast",
        attempts=(_receipt(receipt_id="rcpt-failed", routed_model="", error_code="empty_response", tokens=0),),
    )
    log = RunLog(load_settings())
    try:
        log.start({"kind": "test"}, {"max_tokens": 0, "max_seconds": 0})
        speaker = RecordingLLM(_Inner(done), log)
        speaker.complete("fast", [], Answer)
        events = [event for event in log.events() if event["type"] == "llm_call"]
    finally:
        log.delete()
    assert len(events) == len(speaker.receipts) == 2
    failed, ok = events
    assert failed["payload"]["error_code"] == "empty_response"
    assert failed["payload"]["routed_model"] == ""
    assert failed["payload"]["lane"] == "fast"
    assert ok["payload"]["routed_model"] == "routed-model"
    assert ok["payload"]["requested_model"] == "requested-model"
    assert ok["payload"]["tokens"] == 11
    assert ok["payload"]["latency_ms"] == 42.5


def test_a_failed_call_still_records_its_error_code():
    failed = LLMUnavailable("down", [_receipt(routed_model="", error_code="request_aborted", tokens=0)])
    log = RunLog(load_settings())
    try:
        log.start({"kind": "test"}, {"max_tokens": 0, "max_seconds": 0})
        speaker = RecordingLLM(_Inner(failed), log)
        try:
            speaker.complete("deep", [], Answer)
        except LLMUnavailable:
            pass
        events = [event for event in log.events() if event["type"] == "llm_call"]
    finally:
        log.delete()
    assert len(events) == 1
    assert events[0]["payload"]["error_code"] == "request_aborted"
    assert events[0]["payload"]["lane"] == "fast"
