"""The job queue, the locks, the Nightshift batch client and memory curation."""

from __future__ import annotations

import json
import threading
import uuid

import httpx
import pytest

from sibyl.config import load_settings
from sibyl.jobs import handlers, queue
from sibyl.jobs.locks import LockTimeout, evidence_lock, try_worker_lock
from sibyl.llm.batch import NightshiftBatch


@pytest.fixture
def workspace():
    name = f"jobs-test-{uuid.uuid4().hex[:8]}"
    yield name
    queue.forget_workspace(name)
    with queue.connect() as conn:
        conn.execute("DELETE FROM jobs.jobs WHERE workspace_id = %s", (name,))


def test_dedupe_merge_and_claim_order(workspace):
    # Hold the worker lock so a dev API's scheduler on the same database cannot claim these jobs.
    held = try_worker_lock(workspace)
    assert held is not None
    try:
        _dedupe_merge_and_claim_order(workspace)
    finally:
        held.close()


def _dedupe_merge_and_claim_order(workspace):
    first, created = queue.enqueue(workspace, "repo_sync", trigger="schedule", payload={"repo_id": "r"}, dedupe_key=f"repo_sync:{workspace}")
    again, created_again = queue.enqueue(workspace, "repo_sync", trigger="push", payload={"repo_id": "r"}, dedupe_key=f"repo_sync:{workspace}")
    assert created and not created_again and again["job_id"] == first["job_id"]
    triage, _ = queue.enqueue(workspace, "triage", trigger="schedule", payload={"services": ["a"]})
    merged, created_merge = queue.enqueue(workspace, "triage", trigger="on_change", payload={"services": ["b"]})
    assert not created_merge and merged["job_id"] == triage["job_id"]
    assert merged["payload"]["services"] == ["a", "b"]
    whole, _ = queue.enqueue(workspace, "triage", trigger="manual", payload={"services": None})
    assert whole["payload"]["services"] is None
    manual, created_manual = queue.enqueue(workspace, "triage", trigger="manual", payload={"record_id": "x"}, merge=False)
    assert created_manual
    with queue.connect(autocommit=True) as conn:
        # The merged triage now has priority 0 (a manual request joined it), then the manual run, then the sync.
        order = [queue.claim(workspace, "test", conn)["job_id"] for _ in range(3)]
        assert queue.claim(workspace, "test", conn) is None
    assert order == [triage["job_id"], manual["job_id"], first["job_id"]]


def test_one_worker_lock_per_workspace(workspace):
    held = try_worker_lock(workspace)
    assert held is not None
    try:
        assert try_worker_lock(workspace) is None
    finally:
        held.close()
    again = try_worker_lock(workspace)
    assert again is not None
    again.close()


def test_demo_evidence_lock_excludes_live_work():
    entered = threading.Event()
    release = threading.Event()

    def demo():
        with evidence_lock(exclusive=True):
            entered.set()
            release.wait(10)

    thread = threading.Thread(target=demo)
    thread.start()
    assert entered.wait(10)
    with pytest.raises(LockTimeout):
        with evidence_lock(exclusive=False, wait_seconds=1):
            pass
    release.set()
    thread.join()
    with evidence_lock(exclusive=False, wait_seconds=5):
        with evidence_lock(exclusive=False, wait_seconds=5):
            pass  # live work shares it


def test_activity_feed_reads_after_an_id(workspace):
    first = queue.note(workspace, "sync", "one")
    second = queue.note(workspace, "sync", "two")
    assert [row["title"] for row in queue.activity(workspace)] == ["one", "two"]
    assert [row["activity_id"] for row in queue.activity(workspace, after=first)] == [second]


def _batch_transport(window_ran: str = "now", status: str = "completed", texts=None):
    texts = texts if texts is not None else ['{"rationale": "first"}', "not json"]
    seen: dict = {}

    def handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path.endswith("/jobs"):
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"id": "job_x", "status": "queued", "estimated_start": "2026-10-26T16:30:00Z"})
        if request.method == "POST" and path.endswith("/cancel"):
            seen["cancelled"] = True
            return httpx.Response(200, json={})
        if path.endswith("/jobs/job_x"):
            return httpx.Response(200, json={"id": "job_x", "status": status, "window": window_ran, "generated": len(texts) if status == "completed" else 0})
        seq = int(path.rsplit("/", 1)[1])
        return httpx.Response(
            200,
            json={"seq": seq, "slot": seq, "lane": "fast", "text": texts[seq - 1], "elapsed_ms": 10, "model": {"resolved": "nvidia/nemotron-3.5-lightning-30b-a3b", "honored": True}},
        )

    return httpx.MockTransport(handle), seen


def test_batch_maps_slots_and_leaves_unparsed_answers_empty():
    from sibyl.agents.prioritiser import Rationale

    transport, seen = _batch_transport()
    runner = NightshiftBatch(load_settings(), client=httpx.Client(transport=transport), sleep=lambda _s: None)
    result = runner.run([[{"role": "user", "content": "a"}], [{"role": "user", "content": "b"}]], Rationale, window="quiet")
    assert seen["body"]["window"] == "quiet" and len(seen["body"]["requests"]) == 2
    assert result.outputs[0].rationale == "first" and result.outputs[1] is None
    assert result.window_ran == "now" and result.status == "completed"
    assert result.receipts[0].receipt_id == "job_x#1" and result.receipts[0].mode == "batch"


def test_batch_that_does_not_finish_is_cancelled():
    from sibyl.agents.prioritiser import Rationale

    transport, seen = _batch_transport(status="queued")
    runner = NightshiftBatch(load_settings(), client=httpx.Client(transport=transport), wait_seconds=0, sleep=lambda _s: None)
    result = runner.run([[{"role": "user", "content": "a"}]], Rationale, window="quiet")
    assert result.outputs == [None] and seen.get("cancelled") and "not finished" in result.error


def test_rationales_fall_back_to_chat_for_what_the_batch_missed():
    from sibyl.agents.prioritiser import PlacementResult, Rationale, write_model_rationales
    from sibyl.llm import Completion, Receipt

    class Chat:
        calls = 0

        def complete(self, lane, messages, schema):
            Chat.calls += 1
            return Completion(
                output=Rationale(rationale="from chat"),
                receipt=Receipt(lane=lane, requested_model="r", routed_model="r", receipt_id="c", tokens=1, latency_ms=1, rerouted=False),
                repaired=False,
                fell_back=False,
                lane=lane,
            )

    placed = [
        PlacementResult(case_id=f"c{i}", verdict="affected", score=50 - i, components={}, confidence=0.9, placement="ranked", rationale="")
        for i in range(2)
    ]
    write_model_rationales(placed, Chat(), batch=lambda requests: [Rationale(rationale="from batch"), None])
    assert [item.rationale for item in placed] == ["from batch", "from chat"]
    assert Chat.calls == 1


def test_curation_proposes_lower_trust_after_repeated_disagreement():
    class Memory:
        def __init__(self):
            self.queued = []

        def snapshot(self):
            return {
                "pending": [],
                "resolutions": [{"case_id": "c1", "decision": "not_affected"}, {"case_id": "c2", "decision": "not_affected"}],
            }

        def trust(self, source, field, ecosystem):
            return 0.7

        def resolve(self, payload):
            self.queued.append(payload)
            return {"pending": {"id": "p1"}}

    class World:
        def case(self, case_id):
            return {"placement": {"card": {"ecosystem": "npm", "positions": [{"source": "nvd", "verdict": "affected"}, {"source": "osv", "verdict": "not_affected"}]}}}

    memory = Memory()
    proposals = handlers.curate(memory, World())
    assert [(item["source"], item["ecosystem"], item["weight"]) for item in proposals] == [("nvd", "npm", 0.6)]
    assert memory.queued[0]["scope"] == "adjust_trust"


def test_change_queues_triage_only_for_policies_that_want_it(monkeypatch, workspace):
    services = [
        {"service_id": "on-change", "triage_policy": "on_change"},
        {"service_id": "new-interval", "triage_policy": "interval"},
        {"service_id": "old-interval", "triage_policy": "interval"},
        {"service_id": "manual", "triage_policy": "manual"},
    ]
    monkeypatch.setattr(handlers.store, "list_services", lambda workspace_id, settings=None: services)
    queue.fired("triage:old-interval", workspace)
    try:
        follow = handlers.after_change(workspace, [item["service_id"] for item in services], trigger="on_change", reason="test", settings=load_settings())
    finally:
        with queue.connect() as conn:
            conn.execute("DELETE FROM jobs.schedule WHERE key = 'triage:old-interval'")
    assert follow["services"] == ["new-interval", "on-change"]
