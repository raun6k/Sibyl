"""The queue, schedule, activity and inbox routes, with job execution replaced by a stub."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    import sibyl.jobs.scheduler as scheduler

    ran: list[dict] = []

    def fake_run(job, engines, settings=None):
        ran.append(job)
        return {"stub": True}

    monkeypatch.setattr(scheduler, "run_job", fake_run)
    from sibyl.api.app import app

    with TestClient(app) as test_client:
        test_client.ran = ran  # type: ignore[attr-defined]
        yield test_client


def _wait(predicate, seconds: float = 30) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.5)
    raise AssertionError("timed out")


def test_run_now_schedule_inbox_and_activity(client):
    workspace = client.post("/workspaces", json={"name": "Jobs API test"}).json()["workspace_id"]
    try:
        service = client.post(f"/workspaces/{workspace}/services", json={"name": "api", "team": "core"}).json()
        service_id = service["service_id"]
        patched = client.patch(f"/services/{service_id}", json={"triage_policy": "on_change"})
        assert patched.status_code == 200
        updated = client.patch(f"/workspaces/{workspace}", json={"feed_refresh_minutes": 720})
        assert updated.json()["settings"]["feed_refresh_minutes"] == 720

        schedule = client.get(f"/workspaces/{workspace}/schedule").json()
        assert schedule["feed"]["interval_minutes"] == 720
        assert schedule["services"][0]["next_run"] == "after the next change"

        started = client.post(f"/services/{service_id}/triage")
        assert started.status_code == 202, started.text
        job_id = started.json()["job_id"]
        _wait(lambda: client.get(f"/jobs/{job_id}").json()["status"] == "done")
        [job] = [item for item in client.ran if item["job_id"] == job_id]
        assert job["kind"] == "triage" and job["payload"]["services"] == [service_id]
        assert client.get(f"/workspaces/{workspace}/jobs").json()["jobs"][0]["job_id"] == job_id

        refresh = client.post(f"/workspaces/{workspace}/feeds/refresh")
        assert refresh.status_code == 202

        inbox = client.get(f"/workspaces/{workspace}/inbox").json()
        assert set(inbox["counts"]) == {"questions", "needs_human", "approvals", "total"}

        activity = client.get(f"/workspaces/{workspace}/activity").json()["activity"]
        assert any("started" in row["title"] for row in activity)
    finally:
        _wait(lambda: not any(job["status"] == "running" for job in client.get(f"/workspaces/{workspace}/jobs").json()["jobs"]))
        assert client.delete(f"/workspaces/{workspace}").status_code == 204


def test_demo_dataset_is_checked_before_queueing(client):
    response = client.post("/runs", json={"dataset": "nope"})
    assert response.status_code == 422
