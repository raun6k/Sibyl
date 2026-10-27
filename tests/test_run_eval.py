"""Scoring rules in eval/run_eval.py, on hand-made predictions."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))

import run_eval  # noqa: E402


def _gold(n: int, label: str, *, hard: bool = False, bucket: str = "straightforward") -> dict:
    return {
        "id": f"G{n:03d}",
        "service_id": "svc",
        "purl": f"pkg:npm/p{n}@1.0.0",
        "vuln_id": f"CVE-2026-{n}",
        "label": label,
        "hard": hard,
        "bucket": bucket,
    }


GOLD = [
    _gold(1, "affected"),
    _gold(2, "affected", hard=True, bucket="range_conflict"),
    _gold(3, "not_affected"),
    _gold(4, "not_affected", hard=True, bucket="text_only"),
]


def _key(n: int) -> str:
    return run_eval.case_id(GOLD[n - 1])


def test_missing_counts_as_not_affected_and_uncertain_is_wrong():
    predictions = {
        _key(1): {"prediction": "affected", "confidence": 0.9},
        _key(2): {"prediction": "uncertain", "confidence": 0.5},
        _key(3): {"prediction": "affected", "confidence": 0.95},
    }
    scored = run_eval.score(GOLD, predictions)
    assert (scored["tp"], scored["fp"], scored["fn"], scored["tn"]) == (1, 1, 1, 1)
    assert scored["recall"] == 0.5
    assert scored["precision"] == 0.5
    assert scored["accuracy"] == 0.5
    assert scored["uncertain"] == 1
    assert scored["not_reported"] == 1
    assert scored["confident"] == 2
    assert scored["wrong_confident_rate"] == 0.5


def test_baseline_without_confidence_has_no_wrong_confident_rate():
    scored = run_eval.score(GOLD, {_key(1): {"prediction": "affected"}})
    assert scored["confident"] is None
    assert scored["wrong_confident_rate"] is None


def test_missing_response_is_visible_without_changing_the_scoring_rule():
    rows = run_eval.per_pair([GOLD[2]], {'B4': {}})
    assert rows[0]['said']['B4'] == 'missing'
    assert run_eval._mark('missing', 'not_affected') == '—'
    scored = run_eval.score([GOLD[2]], {})
    assert scored['not_reported'] == 1
    assert scored['accuracy'] == 1.0  # Missing still counts as not affected.


def _report(verdicts: dict[int, tuple[str, str]], conflicts: dict[int, list] | None = None) -> dict:
    report = {"ranked": [], "closed": [], "needs_human": []}
    for n, (branch, verdict) in verdicts.items():
        report[branch].append(
            {
                "case_id": _key(n),
                "verdict": verdict,
                "confidence": 0.9,
                "record_ids": [f"osv:{n}"],
                "positions": [{"source": "osv"}],
                "conflicts": (conflicts or {}).get(n, []),
            }
        )
    return report


def test_escalation_conflicts_and_provenance():
    report = _report({1: ("ranked", "affected"), 2: ("needs_human", "uncertain"), 4: ("needs_human", "uncertain")})
    report["ranked"][0]["record_ids"] = []
    run = {"report": report, "events": [], "summary": {}, "resolutions": []}
    extras = run_eval.sibyl_extras(GOLD, run, {_key(2)})
    assert extras["escalated"] == 2
    assert extras["calibrated_escalation"] == 1.0
    assert extras["conflict_detection"] == 1.0
    assert extras["cases_with_provenance"] == 2 and extras["cases"] == 3


def test_conflict_pairs_include_withdrawn_records():
    candidates = [dict(GOLD[2], positions=[{"source": "ghsa", "status": "withdrawn"}])]
    assert run_eval.conflict_pairs(GOLD, candidates) == {_key(2), _key(3)}


def test_critic_effect_counts_sendbacks_that_changed_the_verdict():
    with_critic = _report({1: ("ranked", "affected"), 2: ("ranked", "affected")})
    without = _report({1: ("ranked", "affected"), 2: ("closed", "not_affected")})
    events = [{"type": "decision", "payload": {"case_id": _key(2), "action": "recheck"}}]
    effect = run_eval.critic_effect(
        GOLD,
        {"report": with_critic, "events": events},
        {"report": without, "events": []},
    )
    assert effect["sendbacks"] == 1
    assert effect["sendbacks_that_changed_verdict"] == 1
    assert effect["accuracy_delta"] == 0.25
    assert effect["gold_changes"][0]["fixed"] is True


def test_markdown_renders_every_section():
    run = {"report": _report({1: ("ranked", "affected")}), "events": [], "summary": {"tokens": 10, "llm_calls": 1, "wall_seconds": 2.0, "cases": 1, "escalations": 0, "branches": {"needs_human": 0}}, "resolutions": []}
    result = {
        "gold": {"pairs": 4, "affected": 2, "hard": 2},
        "systems": {"Sibyl": {**run_eval.score(GOLD, run_eval.predictions_from_report(run["report"])), **run_eval.sibyl_extras(GOLD, run, set())}},
        "runtime": {"Sibyl": run_eval._runtime(run["summary"])},
        "critic_effect": run_eval.critic_effect(GOLD, run, run),
        "memory_effect": run_eval.memory_effect(GOLD, run, run),
        "per_pair": run_eval.per_pair(GOLD, {"Sibyl": run_eval.predictions_from_report(run["report"])}),
    }
    text = run_eval.to_markdown(result)
    for heading in ("## Verdicts", "## Escalation", "## Critic effect", "## Memory effect", "## Runtime", "## Per pair"):
        assert heading in text
