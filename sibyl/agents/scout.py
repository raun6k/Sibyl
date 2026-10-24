"""Scout: rule classifier, plan, and the injection filter.

The model is asked only when the rules do not recognise the request.
Advisory text that matches the filter is quarantined and is not sent on.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

from sibyl.agents.prompts import load_prompt, prompt_version
from sibyl.llm.client import LLMClient
from sibyl.tools.zetaris import readonly_statement

IntentName = Literal["triage", "point_question", "component_query", "explain"]

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_TRIAGE = re.compile(r"\b(weekly triage|run triage|triage run|all services)\b", re.IGNORECASE)
_EXPLAIN = re.compile(r"\b(explain|why did|why is|how did)\b", re.IGNORECASE)
_AFFECTED = re.compile(r"\b(affected|vulnerable|impact)\b", re.IGNORECASE)
_PACKAGE = re.compile(r"\b([A-Za-z0-9_.-]+)@([A-Za-z0-9][A-Za-z0-9.+-]*)")
_PURL = re.compile(r"\bpkg:[a-z0-9]+/")
_INJECTION = re.compile(
    r"ignore (all |any )?(previous|prior|above) instructions"
    r"|disregard (the )?(above|previous|system|rules)"
    r"|you are now"
    r"|system prompt"
    r"|<\s*/?\s*system\s*>"
    r"|do not follow the (system|rules)",
    re.IGNORECASE,
)

_STEPS = {
    "triage": ["map sources", "match ranges", "critique", "prioritise", "report"],
    "point_question": ["select the CVE", "map sources", "match ranges", "critique", "report"],
    "component_query": ["select the component", "map sources", "match ranges", "critique", "report"],
    "explain": ["read the case", "report the evidence"],
}


class ExecutionContract(BaseModel):
    tool: str = "run_sql"
    statements: list[str] = Field(default_factory=lambda: ["SELECT", "WITH"])


class Plan(BaseModel):
    intent: IntentName
    steps: list[str]
    contracts: list[ExecutionContract] = Field(default_factory=lambda: [ExecutionContract()])
    cve_id: str | None = None
    package: str | None = None
    classified_by: Literal["rules", "llm"] = "rules"
    prompt_version: int = 1


class Screen(BaseModel):
    """Quarantined text is not returned. The case continues on structured data."""

    flagged: bool
    text: str | None


class IntentGuess(BaseModel):
    intent: IntentName
    cve_id: str | None = None
    package: str | None = None


def allow_sql(sql: str) -> str:
    """The execution contract: one SELECT or WITH, or the statement is refused."""
    return readonly_statement(sql)


def screen_advisory(text: str) -> Screen:
    if _INJECTION.search(text or ""):
        return Screen(flagged=True, text=None)
    return Screen(flagged=False, text=text)


def classify(request: str, *, llm: LLMClient | None = None) -> Plan:
    ruled = _by_rules(request)
    if ruled is not None:
        return ruled
    if llm is None:
        raise RuntimeError("the request did not match a rule and no model was provided")
    guess = llm.complete(
        "fast",
        [
            {"role": "system", "content": load_prompt("scout")},
            {"role": "user", "content": request},
        ],
        IntentGuess,
    )
    return _plan(
        guess.output.intent,
        cve_id=_normal_cve(guess.output.cve_id),
        package=guess.output.package,
        classified_by="llm",
        prompt_version=prompt_version("scout"),
    )


def _by_rules(request: str) -> Plan | None:
    cve = _CVE.search(request or "")
    cve_id = cve.group(0).upper() if cve else None
    if cve_id and _AFFECTED.search(request):
        return _plan("point_question", cve_id=cve_id)
    if _TRIAGE.search(request):
        return _plan("triage")
    if _EXPLAIN.search(request):
        return _plan("explain", cve_id=cve_id)
    package = _package(request)
    if package or _PURL.search(request or ""):
        return _plan("component_query", package=package, cve_id=cve_id)
    if cve_id:
        return _plan("point_question", cve_id=cve_id)
    return None


def _package(request: str) -> str | None:
    match = _PACKAGE.search(request or "")
    if match is None:
        return None
    return match.group(1)


def _normal_cve(value: str | None) -> str | None:
    if not value:
        return None
    match = _CVE.search(value)
    return match.group(0).upper() if match else None


def _plan(
    intent: IntentName,
    *,
    cve_id: str | None = None,
    package: str | None = None,
    classified_by: Literal["rules", "llm"] = "rules",
    prompt_version: int = 1,
) -> Plan:
    return Plan(
        intent=intent,
        steps=list(_STEPS[intent]),
        cve_id=cve_id,
        package=package,
        classified_by=classified_by,
        prompt_version=prompt_version,
    )
