"""The stage rail leaves Planned before the candidate read finishes."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_demo import _bundles  # noqa: E402

from sibyl.agents.matcher import Evaluation, MatchResult
from sibyl.tools.zetaris import SqlResult


def test_collecting_and_mapping_are_emitted_around_the_long_reads(monkeypatch):
    order: list[str] = []

    class Trace:
        run_id = "run-1"

        def transition(self, before: str, after: str) -> None:
            order.append(f"{before}->{after}")

    def candidates(_settings):
        order.append("candidates")
        return SqlResult("SELECT 1", [], 1, False)

    def texts(_settings):
        order.append("text")
        return []

    def evaluate(rows, observations, llm=None):
        order.append("evaluate")
        return Evaluation(result=MatchResult())

    monkeypatch.setattr("run_demo.load_candidates", candidates)
    monkeypatch.setattr("run_demo.find_text_cases", texts)
    monkeypatch.setattr("run_demo.evaluate", evaluate)
    monkeypatch.setattr("run_demo.osv_listed", lambda _settings: {})
    monkeypatch.setattr("run_demo.load_alias_rows", lambda _settings: [])
    monkeypatch.setattr("run_demo._nvd_text", lambda _settings, _ids: order.append("nvd") or {})
    monkeypatch.setattr("run_demo._severities", lambda _settings, _ids: order.append("severities") or {})

    assert _bundles(None, None, [], None, trace=Trace()) == []
    assert order[0] == "candidates"
    mapping = order.index("COLLECTING->MAPPING")
    assert mapping < order.index("text")
    assert mapping < order.index("nvd")
    assert mapping < order.index("severities")
