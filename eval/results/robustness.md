# Robustness

Overall: PASS. Fixture runs (`tests/fixtures/snapshots`), written by `tests/robustness_check.py`.

## Source outage (DISABLE_SOURCES)

| Disabled | State | Degraded | Ingest receipt | Cases | Ranked / closed / needs human | Confidence lowered | Exploited | EPSS | NVD positions | Text cases | Wall s | Tokens | Check |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| none | DONE | False | all ok | 159 | 129 / 27 / 3 | - | 2 | 141 | 26 | 6 | 386.2 | 61950 | baseline |
| cve_org | DONE | True | disabled | 155 | 128 / 27 / 0 | 0 | 2 | 140 | 27 | 3 | 361.1 | 41562 | pass |
| epss | DONE | True | disabled | 159 | 128 / 27 / 4 | 0 | 2 | 0 | 26 | 6 | 444.0 | 55534 | pass |
| euvd | DONE | True | disabled | 159 | 128 / 27 / 4 | 0 | 2 | 141 | 26 | 6 | 521.7 | 64071 | pass |
| ghsa | DONE | True | disabled | 74 | 62 / 9 / 3 | 1 | 2 | 68 | 26 | 6 | 410.9 | 64364 | pass |
| kev | DONE | True | disabled | 159 | 129 / 27 / 3 | 0 | 0 | 141 | 26 | 6 | 434.2 | 61909 | pass |
| nvd | DONE | True | disabled | 157 | 129 / 25 / 3 | 0 | 2 | 141 | 0 | 4 | 388.1 | 42047 | pass |
| osv | DONE | True | disabled | 142 | 99 / 25 / 18 | 142 | 0 | 123 | 26 | 7 | 564.8 | 109853 | pass |

## Idempotency

PASS

Second ingest of the same snapshots:

- osv: 0 new, 0 changed, 44 unchanged
- ghsa: 0 new, 0 changed, 207 unchanged
- nvd: 0 new, 0 changed, 88 unchanged
- cve_org: 0 new, 0 changed, 17 unchanged
- kev: 0 new, 0 changed, 1754 unchanged
- epss: 0 new, 0 changed, 579 unchanged
- euvd: 0 new, 0 changed, 11 unchanged

World Model ingest: first {'processed': 2700, 'changed': True, 'skippedUnchanged': 0}, second {'processed': 2700, 'changed': False, 'skippedUnchanged': 2700}.

## Covered by unit tests

- 429, 503 and timeout for every source: two retries, then the snapshot, with the source marked degraded (`tests/test_collectors.py::test_every_source_retries_twice_then_falls_back_to_its_snapshot`).
- Prompt injection: a synthetic NVD description with instructions (`tests/fixtures/synthetic/injected-nvd-description.json`) is quarantined on a send-back, never reaches the model, and the structured rows decide (`tests/test_orchestrator.py::test_injected_description_is_quarantined_and_the_rows_decide`). Text-only advisories are screened before extraction (`tests/test_matcher_text.py::test_quarantined_text_is_not_sent_to_the_model`).
