"""API checks: one fixtures run, a second start refused, resolution, and rejected SQL."""

from __future__ import annotations

from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from sibyl.tools.zetaris import SqlRejected, run_sql


def test_fixtures_run_stream_resolution_and_rejected_sql():
    from sibyl.api.app import app

    with TestClient(app) as client:
        started = client.post("/runs", json={"dataset": "fixtures", "disable_sources": [], "window_days": 14})
        assert started.status_code == 202, started.text
        run_id = started.json()["run_id"]
        blocked = client.post("/runs", json={"dataset": "fixtures"})
        assert blocked.status_code == 409
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
            run_sql("DELETE FROM acme_internal.services")
