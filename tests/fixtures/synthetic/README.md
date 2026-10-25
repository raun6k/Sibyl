# Synthetic fixtures

These files are not real API responses. They exist only for cases with no real equivalent: a malformed body and an empty body. HTTP 429 and 5xx are exercised with `httpx.MockTransport` in tests, not with files.

`injected-nvd-description.json` is the validator CVE-2025-56200 NVD description with an instruction appended. `tests/test_orchestrator.py` uses it to check that a send-back never sends that text to the model and that the structured rows decide the case.
