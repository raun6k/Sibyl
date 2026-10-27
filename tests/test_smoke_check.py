"""The documented smoke check validates Sibyl's own seeded workspace."""

import json

import pytest

import smoke_test


ENV = {"ZETARIS_REST_URL": "http://zetaris.invalid", "ZETARIS_API_KEY": "test", "ZETARIS_ORG_ID": "1"}


def test_sql_smoke_queries_the_seeded_sibyl_workspace(monkeypatch):
    def respond(url, *, method, headers, body, timeout):
        assert method == "POST"
        assert "inventory.workspaces" in body["sql"]
        assert "'sample'" in body["sql"]
        return 200, json.dumps({"headers": ["workspace_id"], "data": [["sample"]]}).encode()

    monkeypatch.setattr(smoke_test, "request", respond)
    assert smoke_test.zetaris_sql(ENV).startswith("PASS")


@pytest.mark.parametrize("payload", [
    {"data": []},
    {"data": [["another-workspace"]]},
    {"data": [["sample"], ["unexpected"]]},
    {"error": "inventory is not registered", "data": [["sample"]]},
    {},
])
def test_sql_smoke_rejects_missing_seed_or_failed_query(monkeypatch, payload):
    monkeypatch.setattr(smoke_test, "request", lambda *args, **kwargs: (200, json.dumps(payload).encode()))
    assert smoke_test.zetaris_sql(ENV).startswith("FAIL")
