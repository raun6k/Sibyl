# Synthetic fixtures

These files are not real API responses. They exist only for cases with no real equivalent: a malformed body and an empty body. HTTP 429 and 5xx are exercised with `httpx.MockTransport` in tests, not with files.
