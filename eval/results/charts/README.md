# Result charts

Drawn by `uv run --with matplotlib eval/charts.py` from `eval-full.json` and `robustness.json`. Every chart is in `light/` and `dark/`. The table view for each is in `../eval-full.md` and `../robustness.md`.

| # | File | Message |
|---|---|---|
| 1 | `01-problem-recall-by-bucket.png` | A legacy NVD pipeline misses 15 of 26 real vulnerabilities |
| 2 | `02-gold-set.png` | 40 gold pairs, each labelled from the upstream fix commit |
| 3 | `03-wins.png` | Precision 92.9%, 53× fewer tokens, 689 / 689 sourced, 95% after one answer |
| 4 | `04-per-pair-grid.png` | Where every other system guesses wrong (braces), Sibyl asks a human |
| 5 | `05-cost-per-case.png` | One LLM call per case costs 53× more tokens for the same accuracy |
| 6 | `06-how-each-system-is-wrong.png` | Same accuracy, a safer kind of miss |
| 8 | `08-memory-effect.png` | One human answer: fewer escalations, calls and tokens in run 2 |
| 9 | `09-cpe-join-gap.png` | One data gap explains both wrong answers and the missed conflicts |
| 10 | `10-critic-conflicts.png` | The critic surfaces conflicts (6 of 9 vs 4 of 9); verdicts unchanged here |
| 11 | `11-robustness-outages.png` | Any one source down: the run finishes, marked degraded |
| 12 | `12-robustness-osv-down.png` | OSV down: 18 cases to a human instead of 3, confidence lower on 142 |
| 13 | `13-robustness-defences.png` | Retries and snapshot fallback, injection quarantine, idempotency |
