"""API checks: one fixtures run, a second start refused, resolution, and rejected SQL."""

from __future__ import annotations

from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from sibyl.tools.zetaris import SqlRejected, run_sql


def test_ecosystem_comes_from_the_case_purl():
    from sibyl.api.app import _ecosystem

    assert _ecosystem({"ecosystem": "PyPI"}) == "pypi"
    assert _ecosystem({"case_id": "case:checkout-api:pkg:pypi/djangorestframework@3.14.0:CVE-2024-21520"}) == "pypi"
    assert _ecosystem({"purl": "pkg:npm/decode-uri-component@0.2.0"}) == "npm"
    assert _ecosystem({}) == "*"


@pytest.mark.live
def test_fixtures_run_stream_resolution_and_rejected_sql():
    from sibyl.api.app import app

    with TestClient(app) as client:
        from sibyl.api.app import hub

        if hub is not None:
            hub.hmem.reset()  # a trust change left by an earlier run would block the adjust below
        started = client.post("/runs", json={"dataset": "fixtures", "disable_sources": [], "window_days": 14})
        assert started.status_code == 202, started.text
        run_id = started.json()["run_id"]
        # A second start no longer gets 409: it waits in the queue behind the first.
        queued = client.post("/runs", json={"dataset": "fixtures"})
        assert queued.status_code == 202, queued.text
        second_id = queued.json()["run_id"]
        assert second_id != run_id
        assert client.get(f"/runs/{second_id}").json()["status"] in {"QUEUED", "RUNNING"}
        saw_done = False
        with client.stream("GET", f"/runs/{run_id}/events") as response:
            assert response.status_code == 200
            for line in response.iter_lines():
                if not line:
                    continue
                text = line.decode() if isinstance(line, bytes) else line
                if '"to": "FAILED"' in text or '"to":"FAILED"' in text:
                    raise AssertionError(text)
                if '"to": "DONE"' in text or '"to":"DONE"' in text:
                    saw_done = True
                    break
        assert saw_done
        report = client.get(f"/runs/{run_id}/report")
        assert report.status_code == 200
        body = report.json()
        assert body["state"] == "DONE"
        assert body["receipts"]["zetaris"]
        from sibyl.api.app import hub

        logged = []
        if hub is not None:
            log = hub.runs[run_id].get("log")
            if log is not None:
                logged = [event for event in log.feed() if event.get("type") == "llm_call"]
        assert logged
        for event in logged:
            payload = event.get("payload") or {}
            assert payload.get("routed_model") or payload.get("error_code")
            assert payload.get("lane")
        assert len(logged) == len(body["receipts"]["llm"])
        # The queued run starts after the first. Nothing changed, so it keeps the accepted verdicts.
        _wait_done(client, second_id)
        second = client.get(f"/runs/{second_id}/report").json()
        assert second["reused"], "the second fixtures run reuses unchanged verdicts"
        assert {card["case_id"] for card in second["ranked"] + second["closed"]} == {card["case_id"] for card in body["ranked"] + body["closed"]}
        assert client.get(f"/runs/{second_id}/report.md").text.startswith("# Sibyl report")
        needs = body["needs_human"]
        assert needs
        case_id = quote(needs[0]["case_id"], safe="")
        resolved = client.post(
            f"/cases/{case_id}/resolution",
            json={
                "decision": "affected",
                "note": "confirmed for this case",
                "user": "priya",
                "remember": True,
                "scope": "adjust_trust",
            },
        )
        assert resolved.status_code == 200, resolved.text
        pending = resolved.json()["pending"]
        assert pending and pending["id"]
        approved = client.post(f"/memory/pending/{pending['id']}/approve")
        assert approved.status_code == 200
        assert approved.json()["ok"] is True
        from sibyl.api.app import hub

        if hub is not None:
            hub.hmem.reset()
        with pytest.raises(SqlRejected):
            run_sql("DELETE FROM inventory.services")


def _wait_done(client, run_id: str, seconds: float = 900) -> None:
    import time

    deadline = time.time() + seconds
    while time.time() < deadline:
        status = client.get(f"/runs/{run_id}").json()["status"]
        if status in {"DONE", "FAILED"}:
            assert status == "DONE", client.get(f"/runs/{run_id}").json()
            return
        time.sleep(2)
    raise AssertionError(f"run {run_id} did not finish")


def test_runs_saved_before_p10_keep_their_report(tmp_path):
    from sibyl.api.app import load_runs

    report = {"run_id": "old", "state": "DONE", "ranked": [], "closed": [], "needs_human": []}
    (tmp_path / "old.json").write_text(
        '{"id": "old", "status": "DONE", "started": 1, "report": ' + __import__("json").dumps(report) + "}", encoding="utf-8"
    )
    [record] = load_runs(tmp_path)
    assert record["report"] == report


def test_finished_runs_survive_a_restart(tmp_path):
    from sibyl.api.app import load_runs, save_run
    from sibyl.orchestrator.log import RunLog

    log = RunLog()
    log.run_id = "log-1"
    report = {"run_id": "log-1", "state": "DONE", "ranked": [], "closed": [], "needs_human": []}
    save_run({"id": "b", "status": "DONE", "stage": "DONE", "started": 20.0, "finished": 30.0, "report": report, "log": log}, tmp_path)
    save_run({"id": "a", "status": "FAILED", "stage": "FAILED", "started": 10.0, "finished": 11.0, "error": "zetaris down"}, tmp_path)
    (tmp_path / "broken.json").write_text("{", encoding="utf-8")
    (tmp_path / "running.json").write_text('{"id": "r", "status": "RUNNING"}', encoding="utf-8")

    records = load_runs(tmp_path)

    import json

    saved = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))
    assert "report" not in saved, "run files keep metadata; the report is the World Model's view"
    assert saved["counts"] == {"ranked": 0, "closed": 0, "needs_human": 0}
    assert [record["id"] for record in records] == ["a", "b"]
    assert records[1]["report"] is None
    assert records[1]["log_run_id"] == "log-1"
    assert records[1]["counts"] == {"ranked": 0, "closed": 0, "needs_human": 0}
    assert records[1]["finished"] == 30.0
    assert records[1]["log"].run_id == "log-1"
    assert records[0]["log"] is None and records[0]["degraded_sources"] == []
