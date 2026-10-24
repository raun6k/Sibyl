"""One tiny Nightshift call per lane.

Prints the lane, the requested model, the routed model, and the token
count. This is a live check, not part of pytest.
"""

from __future__ import annotations

import sys

from pydantic import BaseModel

from sibyl.config import load_settings
from sibyl.llm import LLMClient, LLMUnavailable


class Word(BaseModel):
    word: str


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

    failed = False
    with LLMClient(settings) as client:
        for lane in ("fast", "deep", "judge"):
            try:
                done = client.complete(
                    lane,
                    [{"role": "user", "content": 'Reply with {"word": "ok"} and nothing else.'}],
                    Word,
                )
            except LLMUnavailable as exc:
                failed = True
                print(f"FAIL {lane} {exc.reason}")
                for receipt in exc.receipts:
                    _print_receipt(receipt.lane, receipt, fell_back=False, repaired=False, failed=True)
                continue
            _print_receipt(lane, done.receipt, fell_back=done.fell_back, repaired=done.repaired, failed=False)
            if done.fell_back:
                print(f"NOTE {lane} answered on fallback lane {done.lane}")
    return 1 if failed else 0


def _print_receipt(lane, receipt, *, fell_back: bool, repaired: bool, failed: bool) -> None:
    rerouted = "yes" if receipt.rerouted else "no"
    print(
        f"{lane} requested={receipt.requested_model} routed={receipt.routed_model} "
        f"tokens={receipt.tokens} receipt={receipt.receipt_id} rerouted={rerouted} "
        f"latency_ms={receipt.latency_ms} repaired={repaired} fell_back={fell_back} "
        f"failed={failed}"
    )


if __name__ == "__main__":
    sys.exit(main())
