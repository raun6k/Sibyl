"""Load a versioned agent prompt from `prompts/`."""

from __future__ import annotations

import re

from sibyl.config import ROOT

_VERSION = re.compile(r"^Version:\s*(\d+)\s*$", re.MULTILINE)


def load_prompt(agent: str) -> str:
    path = ROOT / "prompts" / f"{agent}.md"
    if not path.is_file():
        raise FileNotFoundError(f"missing prompt {path}")
    return path.read_text(encoding="utf-8")


def prompt_version(agent: str) -> int:
    match = _VERSION.search(load_prompt(agent))
    if match is None:
        raise ValueError(f"prompt {agent} has no Version line")
    return int(match.group(1))
