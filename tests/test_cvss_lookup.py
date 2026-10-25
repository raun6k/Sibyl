"""Severity rows stored under a GHSA id are read for the CVE."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_demo import _severities  # noqa: E402

from sibyl.tools.zetaris import SqlResult


def test_the_severity_query_includes_the_alias_id(monkeypatch):
    def fake(sql, **kwargs):
        if "evidence.vuln_aliases" in sql and "WHERE vuln_id IN" in sql:
            return SqlResult(
                sql,
                [{"vuln_id": "CVE-2024-4340", "alias_id": "GHSA-2m57-hf25-phgg"}],
                1,
                False,
            )
        if "evidence.vuln_aliases" in sql:
            return SqlResult(
                sql,
                [{"vuln_id": "GHSA-2m57-hf25-phgg", "alias_id": "CVE-2024-4340"}],
                1,
                False,
            )
        assert "GHSA-2m57-hf25-phgg" in sql
        assert "CVE-2024-4340" in sql
        return SqlResult(
            sql,
            [
                {
                    "record_id": "ghsa:GHSA-2m57-hf25-phgg",
                    "vuln_id": "GHSA-2m57-hf25-phgg",
                    "source": "ghsa",
                    "score": "7.5",
                    "version": "3.1",
                }
            ],
            1,
            False,
        )

    monkeypatch.setattr("run_demo.run_sql", fake)
    found = _severities(None, ["CVE-2024-4340"])
    assert found["CVE-2024-4340"] == (7.5, "ghsa", "3.1")
