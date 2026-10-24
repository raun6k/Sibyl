"""A full page is marked truncated, and the matcher refuses it."""

import json

from sibyl.agents.matcher import load_candidates
from sibyl.config import Settings
from sibyl.tools.zetaris import ResultTruncated, SqlResult, run_sql


class _Response:
    def __init__(self, payload: dict) -> None:
        self.status = 200
        self._raw = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *args) -> bool:
        return False


def _settings() -> Settings:
    return Settings(
        zetaris_rest_url="http://zetaris.invalid",
        zetaris_api_key="test-key",
        zetaris_org_id="1",
    )


def _payload(rows: int) -> dict:
    return {"headers": ["service_id"], "data": [["checkout-api"] for _ in range(rows)]}


def test_row_count_at_the_limit_is_truncated(monkeypatch):
    monkeypatch.setattr(
        "sibyl.tools.zetaris.urlopen",
        lambda *args, **kwargs: _Response(_payload(2)),
    )
    result = run_sql("SELECT service_id FROM sibyl.v_candidate_matches", settings=_settings(), limit=2)
    assert result.truncated is True
    assert len(result.rows) == 2


def test_row_count_under_the_limit_is_not_truncated(monkeypatch):
    monkeypatch.setattr(
        "sibyl.tools.zetaris.urlopen",
        lambda *args, **kwargs: _Response(_payload(1)),
    )
    result = run_sql("SELECT service_id FROM sibyl.v_candidate_matches", settings=_settings(), limit=2)
    assert result.truncated is False
    assert len(result.rows) == 1


def test_load_candidates_raises_when_a_service_page_is_truncated(monkeypatch):
    def fake(sql: str, **kwargs) -> SqlResult:
        if "acme_internal.services" in sql:
            return SqlResult(sql, [{"service_id": "checkout-api"}], 1, truncated=False)
        return SqlResult(sql, [{"service_id": "checkout-api"}], 1, truncated=True)

    monkeypatch.setattr("sibyl.agents.matcher.run_sql", fake)
    try:
        load_candidates(_settings())
    except ResultTruncated as exc:
        assert "checkout-api" in str(exc)
    else:
        raise AssertionError("truncated page was returned")


def test_load_candidates_pages_each_service_and_does_not_compare_versions(monkeypatch):
    seen: list[str] = []

    def fake(sql: str, **kwargs) -> SqlResult:
        seen.append(sql)
        if "acme_internal.services" in sql:
            return SqlResult(
                sql,
                [{"service_id": "checkout-api"}, {"service_id": "reporting-worker"}],
                1,
                truncated=False,
            )
        return SqlResult(sql, [{"service_id": "checkout-api", "version": "1.0.0"}], 1, truncated=False)

    monkeypatch.setattr("sibyl.agents.matcher.run_sql", fake)
    loaded = load_candidates(_settings())
    assert loaded.truncated is False
    assert any("service_id = 'checkout-api'" in sql for sql in seen)
    assert any("service_id = 'reporting-worker'" in sql for sql in seen)
    assert all("version =" not in sql.lower() for sql in seen)
    assert all("VERSIONS" not in sql for sql in seen)
