"""Service Profiler: propose a service's facts from its code, with quoted evidence.

Evidence is gathered by code: dependency names, `EXPOSE` and `ports:` lines,
Ingress and LoadBalancer settings, CODEOWNERS lines, and environment
variable *names*. No value of an environment variable and no whole source
file is read or sent anywhere. Repository text is attacker-influenced, so
a line that matches the injection filter is dropped before the model sees it.

The model (fast lane) proposes the four facts and must point at evidence
ids it was given; an id it invents is dropped and the confidence capped.
Without a model, the code-only proposal stands, with low confidence.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from sibyl.agents.prompts import load_prompt
from sibyl.agents.scout import screen_advisory
from sibyl.repos.scanner import Candidate

DATA_CLASSES = ("public", "internal", "employee", "customer", "merchant", "cardholder", "credentials", "health")
MAX_EVIDENCE = 40
MAX_LINE = 200
MAX_FILE_BYTES = 200_000
_ENV_NAME = re.compile(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*[=:]")
_EXPOSE = re.compile(r"^\s*EXPOSE\s+(.+)$", re.IGNORECASE)
_DOCKER_ENV = re.compile(r"^\s*ENV\s+([A-Z][A-Z0-9_]{2,})", re.IGNORECASE)
_PORTS = re.compile(r"^\s*-?\s*[\"']?\d{2,5}(:\d{2,5})?[\"']?\s*$|^\s*ports\s*:", re.IGNORECASE)
_K8S_PUBLIC = re.compile(r"kind:\s*Ingress|type:\s*LoadBalancer|kind:\s*Gateway|kind:\s*HTTPRoute", re.IGNORECASE)

WEB_FRAMEWORKS = {
    "npm": {"express", "fastify", "koa", "next", "@nestjs/core", "hapi", "@hapi/hapi", "nuxt", "@remix-run/node"},
    "pypi": {"django", "flask", "fastapi", "starlette", "aiohttp", "tornado", "sanic", "uvicorn", "gunicorn"},
    "maven": {"org.springframework.boot:spring-boot-starter-web", "org.springframework:spring-web", "io.javalin:javalin", "io.micronaut:micronaut-http-server"},
    "golang": {"github.com/gin-gonic/gin", "github.com/labstack/echo/v4", "github.com/gofiber/fiber/v2", "github.com/gorilla/mux", "github.com/go-chi/chi/v5"},
}
SENSITIVE_PACKAGES = {
    "cardholder": ("stripe", "braintree", "adyen", "paypal", "square", "checkout-sdk"),
    "credentials": ("passport", "jsonwebtoken", "pyjwt", "bcrypt", "argon2", "oauthlib", "authlib", "keycloak", "jwt"),
    "customer": ("twilio", "sendgrid", "mailgun", "segment", "intercom"),
    "health": ("fhir", "hl7"),
}
SENSITIVE_ENV = {
    "cardholder": ("STRIPE", "BRAINTREE", "ADYEN", "PAYPAL", "CARD", "PAYMENT"),
    "credentials": ("JWT", "SECRET", "OAUTH", "AUTH", "PASSWORD", "SESSION"),
    "customer": ("CUSTOMER", "SMTP", "SENDGRID", "TWILIO"),
}
_CONFIG_FILES = ("Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", "Procfile", "fly.toml", "app.yaml", "serverless.yml", ".env.example", ".env.sample", "env.example")
_DEPLOY_DIRS = ("k8s", "kubernetes", "deploy", "deployment", "helm", "charts", "manifests", "infra")


class FactGuess(BaseModel):
    value: Any = None
    confidence: float = Field(default=0.3, ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)
    reason: str = ""


class ServiceProfile(BaseModel):
    internet_facing: FactGuess
    team: FactGuess
    criticality: FactGuess
    data_class: FactGuess


@dataclass
class Evidence:
    id: str
    file: str
    line: int
    signal: str
    text: str

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "file": self.file, "line": self.line, "signal": self.signal, "text": self.text}


@dataclass
class Proposal:
    facts: dict[str, dict[str, Any]]
    evidence: list[Evidence]
    by: str  # "model" or "code"
    dropped_lines: int = 0
    receipts: list[dict[str, Any]] = field(default_factory=list)


def gather(root: Path, candidate: Candidate) -> tuple[list[Evidence], int]:
    """Evidence lines for one service. Returns (evidence, lines dropped by the injection filter)."""
    found: list[Evidence] = []
    dropped = 0
    base = root / candidate.path if candidate.path else root

    def add(file: Path | str, line: int, signal: str, text: str) -> None:
        nonlocal dropped
        clean = " ".join(str(text).split())[:MAX_LINE]
        if not clean:
            return
        if screen_advisory(clean).flagged:
            dropped += 1
            return
        relative = str(file.relative_to(root)) if isinstance(file, Path) else file
        found.append(Evidence(id=f"e{len(found) + 1}", file=relative, line=line, signal=signal, text=clean))

    for item in candidate.components:
        if item.direct and _is_framework(item.component.ecosystem, item.component.name):
            add(item.source_file or "(manifest)", 0, "web_framework", f"depends on {item.component.name} {item.component.version}")
    for item in candidate.components:
        if not item.direct:
            continue
        lowered = item.component.name.lower()
        for data_class, needles in SENSITIVE_PACKAGES.items():
            if any(needle in lowered for needle in needles):
                add(item.source_file or "(manifest)", 0, f"package:{data_class}", f"depends on {item.component.name}")
                break

    for path in _config_files(root, base):
        name = path.name
        for number, line in _lines(path):
            if name.startswith("Dockerfile"):
                exposed = _EXPOSE.match(line)
                if exposed:
                    add(path, number, "exposed_port", line)
                named = _DOCKER_ENV.match(line)
                if named:
                    add(path, number, "env_name", f"ENV {named.group(1)}")
            elif name.startswith((".env", "env.")):
                named = _ENV_NAME.match(line)
                if named:
                    add(path, number, "env_name", named.group(1))
            elif path.suffix in {".yml", ".yaml"}:
                if _K8S_PUBLIC.search(line):
                    add(path, number, "public_route", line)
                elif _PORTS.match(line) and "compose" in name:
                    add(path, number, "exposed_port", line)
                elif "host:" in line.lower() and "ingress" in path.as_posix().lower():
                    add(path, number, "public_route", line)
            else:
                if re.search(r"\bport\b|\bhttp\b|web:", line, re.IGNORECASE):
                    add(path, number, "exposed_port", line)
            if len(found) >= MAX_EVIDENCE:
                break

    for path in (root / "CODEOWNERS", root / ".github" / "CODEOWNERS", root / "docs" / "CODEOWNERS"):
        for number, line in _lines(path):
            owner = _codeowner(line, candidate.path)
            if owner:
                add(path, number, "codeowners", line)
    return found[:MAX_EVIDENCE], dropped


def code_only(candidate: Candidate, evidence: list[Evidence]) -> dict[str, dict[str, Any]]:
    """A proposal from the evidence alone, with low confidence."""
    signals = {item.signal for item in evidence}
    public = "public_route" in signals
    serving = public or "exposed_port" in signals or "web_framework" in signals
    data_class = "internal"
    data_evidence: list[str] = []
    for wanted in ("cardholder", "credentials", "health", "customer"):
        hits = [item.id for item in evidence if item.signal == f"package:{wanted}"]
        hits += [item.id for item in evidence if item.signal == "env_name" and any(key in item.text.upper() for key in SENSITIVE_ENV.get(wanted, ()))]
        if hits:
            data_class = wanted
            data_evidence = hits[:4]
            break
    owners = [item for item in evidence if item.signal == "codeowners"]
    team = _codeowner(owners[-1].text, candidate.path) if owners else ""
    criticality = 1.0 if data_class in {"cardholder", "credentials"} else 0.8 if public else 0.5 if serving else 0.3
    exposure_ids = [item.id for item in evidence if item.signal in {"public_route", "exposed_port", "web_framework"}][:4]
    return {
        "internet_facing": {"value": public, "confidence": 0.6 if public else 0.35, "evidence": exposure_ids, "reason": "found an ingress or load balancer" if public else "no public route found in the repository"},
        "team": {"value": team, "confidence": 0.7 if team else 0.2, "evidence": [owners[-1].id] if owners else [], "reason": "CODEOWNERS" if team else "no owner named"},
        "criticality": {"value": criticality, "confidence": 0.3, "evidence": data_evidence or exposure_ids[:2], "reason": "estimated from exposure and data handled"},
        "data_class": {"value": data_class, "confidence": 0.45 if data_evidence else 0.25, "evidence": data_evidence, "reason": "dependencies and variable names" if data_evidence else "nothing sensitive named"},
    }


def propose(root: Path, candidate: Candidate, llm: Any | None = None) -> Proposal:
    evidence, dropped = gather(root, candidate)
    fallback = code_only(candidate, evidence)
    if llm is None:
        return Proposal(facts=fallback, evidence=evidence, by="code", dropped_lines=dropped)
    payload = {
        "service": {
            "name": candidate.name,
            "path": candidate.path or "(repository root)",
            "ecosystems": candidate.ecosystems,
            "direct_dependencies": sorted({item.component.name for item in candidate.components if item.direct})[:60],
        },
        "evidence": [item.as_dict() for item in evidence],
    }
    try:
        done = llm.complete(
            "fast",
            [
                {"role": "system", "content": load_prompt("profiler")},
                {"role": "user", "content": json.dumps(payload)},
            ],
            ServiceProfile,
        )
    except Exception:
        return Proposal(facts=fallback, evidence=evidence, by="code", dropped_lines=dropped)
    output = done.output if hasattr(done, "output") else done
    try:
        facts = _checked(output, {item.id for item in evidence})
    except (ValidationError, ValueError, TypeError):
        return Proposal(facts=fallback, evidence=evidence, by="code", dropped_lines=dropped)
    return Proposal(facts=facts, evidence=evidence, by="model", dropped_lines=dropped)


def _checked(profile: ServiceProfile, known: set[str]) -> dict[str, dict[str, Any]]:
    """Keep only evidence ids that exist; normalise values; cap unsupported confidence."""
    facts: dict[str, dict[str, Any]] = {}
    for name in ("internet_facing", "team", "criticality", "data_class"):
        guess: FactGuess = getattr(profile, name)
        cited = [ref for ref in guess.evidence if ref in known]
        confidence = guess.confidence if cited else min(guess.confidence, 0.4)
        value = guess.value
        if name == "internet_facing":
            value = value if isinstance(value, bool) else str(value).strip().lower() in {"true", "yes", "1"}
        elif name == "criticality":
            value = max(0.0, min(1.0, float(value if value is not None else 0.5)))
        elif name == "data_class":
            value = str(value or "internal").strip().lower()
            if value not in DATA_CLASSES:
                value = "internal"
                confidence = min(confidence, 0.3)
        else:
            value = _team_name(str(value or ""))
        facts[name] = {"value": value, "confidence": round(confidence, 3), "evidence": cited, "reason": guess.reason[:240]}
    return facts


def _team_name(raw: str) -> str:
    """`@org/payments` and `org/payments` are the team `payments`; an email stays as written."""
    text = raw.strip()
    if "@" in text[1:]:
        return text[:80]
    return text.lstrip("@").split("/")[-1].strip()[:80]


def _is_framework(ecosystem: str, name: str) -> bool:
    return name.lower() in {item.lower() for item in WEB_FRAMEWORKS.get(ecosystem, set())}


def _config_files(root: Path, base: Path) -> list[Path]:
    files: list[Path] = []
    for name in _CONFIG_FILES:
        for folder in (base, root) if base != root else (root,):
            path = folder / name
            if path.is_file() and path not in files:
                files.append(path)
    for path in sorted(base.glob("Dockerfile*")):
        if path.is_file() and path not in files:
            files.append(path)
    service_name = base.name.lower()
    for folder in [base / name for name in _DEPLOY_DIRS] + [root / name for name in _DEPLOY_DIRS]:
        if not folder.is_dir():
            continue
        for path in sorted(folder.rglob("*.y*ml"))[:200]:
            if not path.is_file():
                continue
            inside = base in path.parents
            if inside or service_name in path.as_posix().lower():
                files.append(path)
    return files[:60]


def _lines(path: Path) -> list[tuple[int, str]]:
    if not path.is_file():
        return []
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [(index, line) for index, line in enumerate(text.splitlines(), start=1)]


def _codeowner(line: str, service_path: str) -> str:
    """The first owner when the CODEOWNERS pattern covers `service_path`, else ""."""
    text = line.split("#", 1)[0].strip()
    parts = text.split()
    if len(parts) < 2:
        return ""
    pattern, owners = parts[0], parts[1:]
    target = "/" + (service_path.strip("/") + "/" if service_path else "")
    normal = pattern if pattern.startswith("/") else "/**/" + pattern
    if pattern == "*" or fnmatch.fnmatch(target, normal.rstrip("/") + "*") or target.startswith(pattern.rstrip("*")):
        owner = owners[0].lstrip("@")
        return owner.split("/")[-1]
    return ""


QUESTION_TEXT = {
    "internet_facing": "Is {service} reachable from the internet? Sibyl thinks it is {value}.",
    "team": "Which team owns {service}? Sibyl thinks: {value}.",
    "criticality": "How critical is {service}? Sibyl proposes {value} (0 low, 1 handles money or logins).",
    "data_class": "What is the most sensitive data {service} handles? Sibyl thinks: {value}.",
}


def question_text(name: str, service: str, value: Any) -> str:
    shown = value
    if name == "internet_facing":
        shown = "internet-facing" if value else "not internet-facing"
    elif name == "team" and not value:
        shown = "no team named"
    return QUESTION_TEXT[name].format(service=service, value=shown)


def path_label(path: str) -> str:
    return str(PurePosixPath(path)) if path else "(repository root)"
