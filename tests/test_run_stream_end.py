"""Completed traces terminate explicitly, without inventing an extra trace event."""
import json
from types import SimpleNamespace

from sibyl.api import app
from sibyl.orchestrator.log import RunLog


def test_finished_historical_trace_has_explicit_end_after_every_record(monkeypatch):
    monkeypatch.setattr(app, 'load_settings', lambda: SimpleNamespace(run_max_seconds=1))
    events = [{'event_id': str(i), 'type': 'tool', 'actor': 'mapper', 'payload': {'rows': i}} for i in range(345)]
    log = RunLog.__new__(RunLog)
    log.run_id = 'recorded-run'
    log.feed = lambda after: events
    frames = list(app._stream({'status': 'DONE', 'log': log, 'report': {}}, None))
    assert len(frames) == len(events) + 1
    assert all(f'id: {i}\n' in frames[i] for i in range(345))
    assert frames[-1].startswith('event: end\n')
    assert json.loads(frames[-1].split('data: ')[1]) == {'status': 'DONE', 'events': 345}


def test_empty_finished_trace_is_complete_without_a_fake_agent_event(monkeypatch):
    monkeypatch.setattr(app, 'load_settings', lambda: SimpleNamespace(run_max_seconds=1))
    frames = list(app._stream({'status': 'FAILED'}, None))
    assert len(frames) == 1 and frames[0].startswith('event: end\n')


def test_connection_timeout_does_not_mark_the_run_failed(monkeypatch):
    monkeypatch.setattr(app, 'load_settings', lambda: SimpleNamespace(run_max_seconds=-121))
    record = {'status': 'RUNNING'}
    frames = list(app._stream(record, None))
    assert frames[0].startswith('event: trace_error\n')
    assert record['status'] == 'RUNNING'
