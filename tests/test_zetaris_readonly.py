"""run_sql refuses anything that is not a single read."""

import pytest

from sibyl.tools.zetaris import SqlRejected, readonly_statement, run_sql


@pytest.mark.parametrize("failures", [1, 2, 3])
def test_jdbc_connection_failure_retries_reads_with_a_bound(monkeypatch, failures):
    import io
    from urllib.error import HTTPError
    from sibyl.config import Settings
    from sibyl.tools import zetaris

    calls = []
    sleeps = []

    class Response:
        status = 200
        def read(self):
            return b'{"headers":["n"],"data":[[422]]}'
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    def send(*args, **kwargs):
        calls.append(1)
        if len(calls) <= failures:
            body = b'{"msg":"org.postgresql.util.PSQLException: The connection attempt failed."}'
            raise HTTPError('http://zetaris.invalid', 400, 'Bad request', {}, io.BytesIO(body))
        return Response()

    monkeypatch.setattr(zetaris, 'urlopen', send)
    monkeypatch.setattr(zetaris.time, 'sleep', sleeps.append)
    settings = Settings(zetaris_rest_url='http://zetaris.invalid', zetaris_api_key='test')
    if failures == 3:
        with pytest.raises(RuntimeError, match='connection attempt failed'):
            run_sql('SELECT count(*) FROM inventory.components', settings=settings)
    else:
        assert run_sql('SELECT count(*) FROM inventory.components', settings=settings).rows == [{'n': '422'}]
    assert len(calls) == min(failures + 1, 3)
    assert sleeps == list(range(1, min(failures, 2) + 1))


def test_syntax_errors_and_admin_statements_are_never_retried(monkeypatch):
    from sibyl.tools import zetaris
    calls = []
    def fail(*args, **kwargs):
        calls.append(1)
        raise RuntimeError('syntax error')
    monkeypatch.setattr(zetaris, '_post', fail)
    with pytest.raises(RuntimeError, match='syntax error'):
        run_sql('SELECT broken')
    assert len(calls) == 1
    calls.clear()
    def jdbc(*args, **kwargs):
        calls.append(1)
        raise zetaris._TransientJdbcError('connection attempt failed')
    monkeypatch.setattr(zetaris, '_post', jdbc)
    with pytest.raises(RuntimeError, match='connection attempt failed'):
        zetaris.run_admin('RUN DQ inventory')
    assert len(calls) == 1


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
