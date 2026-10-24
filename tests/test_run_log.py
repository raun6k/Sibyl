"""Run events land in Postgres and secrets do not."""

from __future__ import annotations

import json

from sibyl.config import load_settings
from sibyl.llm import Receipt
from sibyl.orchestrator.log import RunLog


def test_run_log_appends_each_kind_and_redacts_secrets():
    settings = load_settings()
    log = RunLog(settings)
    log.start({"sample": True, "url": settings.database_url}, {"max_tokens": settings.run_max_tokens})
    try:
        log.transition("PLANNED", "COLLECTING")
        log.agent_step("mapper", "source map", case_id="case:demo")
        log.tool_call("matcher", "SELECT 1", rows=2, ms=3.5)
        log.llm_call(
            "critic",
            Receipt(
                lane="deep",
                requested_model="nvidia/requested",
                routed_model="nvidia/routed",
                receipt_id="rcpt-log",
                tokens=9,
                latency_ms=4,
                rerouted=True,
            ),
        )
        log.decision("critic", settings.database_url, case_id="case:demo")
        assert log.status() == "COLLECTING"
        events = log.events()
    finally:
        log.delete()

    assert [event["type"] for event in events] == [
        "state",
        "state",
        "agent_step",
        "tool_call",
        "llm_call",
        "decision",
    ]
    assert events[0]["payload"] == {"to": "PLANNED"}
    assert events[1]["payload"] == {"from": "PLANNED", "to": "COLLECTING"}
    assert events[1]["actor"] == "orchestrator"
    tool = events[3]["payload"]
    assert tool == {"sql": "SELECT 1", "rows": 2, "ms": 3.5}
    receipt = events[4]["payload"]
    assert receipt["lane"] == "deep"
    assert receipt["requested_model"] == "nvidia/requested"
    assert receipt["routed_model"] == "nvidia/routed"
    assert receipt["rerouted"] is True
    assert receipt["receipt_id"] == "rcpt-log"
    stored = json.dumps(events)
    assert settings.database_url not in stored
    assert "***" in stored
    if settings.meterless_runtime_token:
        assert settings.meterless_runtime_token not in stored
