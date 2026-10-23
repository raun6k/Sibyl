"""run_sql refuses anything that is not a single read."""

import pytest

from sibyl.tools.zetaris import SqlRejected, readonly_statement, run_sql


def test_select_and_with_are_allowed():
    assert readonly_statement("SELECT 1") == "SELECT 1"
    assert readonly_statement("  WITH c AS (SELECT 1) SELECT * FROM c; ") == (
        "WITH c AS (SELECT 1) SELECT * FROM c"
    )


def test_writes_and_multiple_statements_are_refused():
    refused = [
        "INSERT INTO evidence.affected VALUES (1)",
        "UPDATE evidence.affected SET package = 'x'",
        "DELETE FROM evidence.affected",
        "DROP TABLE evidence.affected",
        "CREATE TABLE t (id int)",
        "CACHE TABLE sibyl_feeds.v_kev",
        "SELECT 1; DROP TABLE evidence.affected",
    ]
    for sql in refused:
        with pytest.raises(SqlRejected):
            run_sql(sql)
