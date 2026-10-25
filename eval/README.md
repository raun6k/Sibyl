# Eval

Scores Sibyl and four baselines against the reviewed gold set, and checks robustness. The narrative and charts are in the main [README](../README.md#results).

| Path | What it is |
|---|---|
| `gold/` | The 40 labelled pairs, the picks, and how they were chosen ([gold/README.md](gold/README.md)) |
| `baselines.py` | B1 NVD-CPE-only, B2 OSV-only, B3 naive union, over every candidate pair |
| `collect_runs.py` | Live runs: baselines, Sibyl run 1, run 2, Sibyl − critic, B4 single-pass LLM |
| `run_eval.py` | Scores the saved runs; writes `results/eval-full.{md,json}` |
| `charts.py` | Draws `results/charts/{light,dark}/` from the results |
| `results/runs/` | Report, trace and summary for each Sibyl run |
| `results/robustness.{md,json}` | Written by `tests/robustness_check.py` |
| `results/engines/` | World Model and H-MEM conformance output |

## Reproduce

Zetaris, Nightshift and Postgres must be running, and the full snapshots must be in `data/sample/snapshots/`.

```text
uv run eval/collect_runs.py              # about 30 minutes; ingests once, then every run
uv run eval/collect_runs.py --only-b4    # rerun B4 alone on the evidence already loaded
uv run eval/run_eval.py                  # score; no live calls
uv run tests/robustness_check.py         # about 30 minutes on the fixtures
uv run --with matplotlib eval/charts.py
```

`collect_runs.py` gives each run a 1800-second budget, so the full set is not cut short, and resets H-MEM when it finishes. Run 2 follows resolving the run-1 needs-human gold pairs with their reviewed labels, so the memory section also reports accuracy on the pairs that were not resolved.

## Scoring rules

- The positive class is `affected`. A pair a system never reports counts as `not_affected`.
- Every needs-human case is `uncertain`, whatever its draft verdict. It is not a positive and is wrong for accuracy.
- Confident means confidence ≥ 0.8.
- Calibrated escalation uses the gold `hard` flag.
- Gold conflicts are the range-conflict bucket plus withdrawn records. A conflict counts as surfaced when the case has a recorded conflict, a critic recheck or reject, or a needs-human placement.
- Critic effect counts run-1 send-backs whose verdict differs in the run without the critic.
