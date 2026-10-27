"""Human review filtering, including saved decisions and pending trust proposals."""
from types import SimpleNamespace

from sibyl.api.review_queue import unresolved_cases


def test_saved_resolutions_leave_review_but_pending_and_expired_cases_remain():
    # The store's resolution_for API returns only active this_case resolutions.
    cards = [{"case_id": name} for name in ("saved", "pending_trust", "expired", "unanswered")]
    memory = SimpleNamespace(resolution_for=lambda case_id: {"decision": "affected"} if case_id == "saved" else None)
    assert unresolved_cases(cards, memory) == cards[1:]
    assert len(cards) == 4  # The recorded report is not rewritten.


def test_memory_failure_keeps_the_case_visible():
    def unavailable(_):
        raise RuntimeError("memory unavailable")

    cards = [{"case_id": "still-needs-review"}]
    assert unresolved_cases(cards, SimpleNamespace(resolution_for=unavailable)) == cards


def test_needs_human_filters_current_and_legacy_report_paths(monkeypatch):
    from sibyl.api import app

    cards = [{"case_id": "saved"}, {"case_id": "open"}]
    memory = SimpleNamespace(resolution_for=lambda case_id: {} if case_id == "saved" else None)
    monkeypatch.setattr(app, "_hub", lambda: SimpleNamespace(hmem_for=lambda workspace: memory))
    monkeypatch.setattr(app, "_latest_report_or_none", lambda workspace: {"run_id": "run"})
    monkeypatch.setattr(app, "current_cards", lambda workspace: [{"card": card, "placement": "needs_human", "run_id": "run"} for card in cards])
    assert [card["case_id"] for card in app.needs_human("workspace")["needs_human"]] == ["open"]
    monkeypatch.setattr(app, "current_cards", lambda workspace: None)
    monkeypatch.setattr(app, "_latest_report", lambda workspace: {"run_id": "run", "needs_human": cards})
    assert app.needs_human("workspace")["needs_human"] == [cards[1]]


def test_inbox_counts_exclude_saved_cases(monkeypatch):
    from sibyl.api import app, workspaces

    cards = [{"case_id": "saved"}, {"case_id": "open"}]
    memory = SimpleNamespace(resolution_for=lambda case_id: {} if case_id == "saved" else None, snapshot=lambda: {"pending": [{"id": "trust"}]})
    monkeypatch.setattr(workspaces, "_workspace_or_404", lambda workspace: None)
    monkeypatch.setattr(workspaces.store, "list_questions", lambda *args: [])
    monkeypatch.setattr(workspaces, "_active", lambda: SimpleNamespace(hmem_for=lambda workspace: memory))
    monkeypatch.setattr(app, "current_cards", lambda workspace: [{"card": card, "placement": "needs_human"} for card in cards])
    inbox = workspaces.get_inbox("workspace")
    assert [card["case_id"] for card in inbox["needs_human"]] == ["open"]
    assert inbox["counts"] == {"questions": 0, "needs_human": 1, "approvals": 1, "total": 2}
