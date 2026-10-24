"""One extraction call per Nightshift lane.

Uses the Matcher prompt and a short advisory, not a one-word reply.
Prints the lane, requested model, routed model, tokens, reasoning
tokens, latency, and error code. This is a live check, not part of pytest.
"""

from __future__ import annotations

import json
import sys
import time

from sibyl.agents.matcher import ExtractedRange
from sibyl.agents.prompts import load_prompt
from sibyl.config import load_settings
from sibyl.llm import LLMClient, LLMUnavailable

_PAYLOAD = {
    "package": "xml2js",
    "version": "0.4.23",
    "ecosystem": "npm",
    "vuln_id": "CVE-2023-0842",
    "text": (
        "xml2js versions before 0.5.0 are affected. "
        "The CNA lists node-xml2js 0.4.23 as affected."
    ),
    "affected": [
        {
            "product": "node-xml2js",
            "defaultStatus": "unaffected",
            "versions": [{"version": "0.4.23", "status": "affected"}],
        }
    ],
}


def main() -> int:
    settings = load_settings()
    missing = [
        name
        for name, value in (
            ("METERLESS_BASE_URL", settings.meterless_base_url),
            ("METERLESS_RUNTIME_TOKEN", settings.meterless_runtime_token),
            ("METERLESS_MODEL_FAST", settings.meterless_model_fast),
            ("METERLESS_MODEL_DEEP", settings.meterless_model_deep),
            ("METERLESS_MODEL_JUDGE", settings.meterless_model_judge),
        )
        if not value
    ]
    if missing:
        print("FAIL missing " + ", ".join(missing))
        return 1
    print(f"max_tokens={settings.meterless_max_tokens}")
    messages = [
        {"role": "system", "content": load_prompt("matcher")},
        {"role": "user", "content": json.dumps(_PAYLOAD)},
    ]
    print(f"prompt_chars={sum(len(message['content']) for message in messages)}")

    failed = False
    with LLMClient(settings) as client:
        for lane in ("fast", "deep", "judge"):
            started = time.perf_counter()
            try:
                done = client.complete(lane, messages, ExtractedRange)
            except LLMUnavailable as exc:
                failed = True
                wall_ms = (time.perf_counter() - started) * 1000
                print(f"FAIL {lane} wall_ms={wall_ms:.0f} {exc.reason}")
                for receipt in exc.receipts:
                    _print_receipt(receipt.lane, receipt, fell_back=False, repaired=False, failed=True)
                continue
            wall_ms = (time.perf_counter() - started) * 1000
            for receipt in done.attempts:
                _print_receipt(receipt.lane, receipt, fell_back=False, repaired=False, failed=True)
            _print_receipt(
                lane,
                done.receipt,
                fell_back=done.fell_back,
                repaired=done.repaired,
                failed=False,
                wall_ms=wall_ms,
            )
            if done.fell_back:
                print(f"NOTE {lane} answered on fallback lane {done.lane}")
    return 1 if failed else 0


def _print_receipt(lane, receipt, *, fell_back: bool, repaired: bool, failed: bool, wall_ms: float | None = None) -> None:
    rerouted = "yes" if receipt.rerouted else "no"
    wall = f" wall_ms={wall_ms:.0f}" if wall_ms is not None else ""
    print(
        f"{lane} requested={receipt.requested_model} routed={receipt.routed_model} "
        f"tokens={receipt.tokens} reasoning_tokens={receipt.reasoning_tokens} "
        f"receipt={receipt.receipt_id} rerouted={rerouted} "
        f"latency_ms={receipt.latency_ms:.0f}{wall} error={receipt.error_code or '-'} "
        f"repaired={repaired} fell_back={fell_back} failed={failed}"
    )


if __name__ == "__main__":
    sys.exit(main())
