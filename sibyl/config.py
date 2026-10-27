"""Runtime settings loaded from the environment and the repo `.env`.

Secrets stay out of logs: the database URL, the NVD key, the GitHub token,
the Zetaris key, and the Nightshift runtime token are excluded from the
model repr and stripped by `redact`.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field

ROOT = Path(__file__).resolve().parents[1]

# Default trust from docs/project/data.md. H-MEM replaces this table in P4.
DEFAULT_TRUST: dict[str, float] = {
    "osv": 0.95,
    "ghsa": 0.9,
    "cna": 0.8,
    "cisa-adp": 0.8,
    "euvd": 0.75,
    "nvd-cpe": 0.7,
    "nvd": 0.7,
    "llm-extracted": 0.5,
}


def _as_int(value: str | None, default: int) -> int:
    if value is None or value.strip() == "":
        return default
    return int(value.strip())


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Settings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    database_url: str = Field(default="", repr=False)
    sample_mode: bool = True
    contact_email: str = ""
    nvd_api_key: str = Field(default="", repr=False)
    github_token: str = Field(default="", repr=False)
    disable_sources: str = ""
    snapshot_dir: str = "data/sample/snapshots"
    zetaris_rest_url: str = ""
    zetaris_org_id: str = "1"
    zetaris_api_key: str = Field(default="", repr=False)
    meterless_base_url: str = "http://127.0.0.1:8088/v1"
    meterless_runtime_token: str = Field(default="", repr=False)
    # Nightshift routing modes, not model ids. The Sibyl fleet's lanes decide which
    # Nemotron model answers; the receipt says whether the mode was honoured.
    meterless_model_fast: str = "meterless/fast"
    meterless_model_deep: str = "meterless/deep"
    meterless_model_critic: str = "meterless/fusion"
    meterless_model_judge: str = "meterless/fusion"
    # Completion cap for every lane. 512 ends before a reasoning model writes any text.
    meterless_max_tokens: int = 8192
    run_max_seconds: int = 600
    run_max_tokens: int = 400_000
    # Off for the "Sibyl without the critic" ablation: the Matcher's verdict stands,
    # with no send-backs, quote checks, withdrawn checks, or second round.
    critic_enabled: bool = True
    # Priority weights from agents.md. The score is the sum of these terms.
    weight_exploited: float = 40
    weight_epss: float = 20
    weight_severity: float = 15
    weight_exposure: float = 15
    weight_criticality: float = 10
    # A score at least this large is "high" for the 0.5–0.8 confidence band.
    # 40 is the exploited term on its own.
    high_priority_min: float = 40
    confidence_llm_factor: float = 0.6
    confidence_blocking_factor: float = 0.7
    confidence_degraded_factor: float = 0.8
    trust_weights: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_TRUST))
    # The workspace a triage or ingest reads. Empty reads every active service.
    workspace_id: str = ""
    # Live NVD and CVE.org fetch these CVE ids instead of a time window.
    target_cves: list[str] = Field(default_factory=list)
    # SBOM generator for repository scans, and where cloned repositories live.
    cdxgen_cmd: str = "npx --yes @cyclonedx/cdxgen@12.9.0"
    repos_dir: str = "var/repos"
    # The API's scheduler queues repository polls, feed refreshes and interval triages.
    # Off (SIBYL_SCHEDULER=false) only stops the clock; queued jobs still run.
    scheduler_enabled: bool = True

    def meterless_max_tokens_for(self, lane: str) -> int:
        if lane not in {"fast", "deep", "critic", "judge"}:
            raise ValueError(f"unknown lane {lane!r}")
        return self.meterless_max_tokens

    def disabled_sources(self) -> set[str]:
        return {part.strip().lower() for part in self.disable_sources.split(",") if part.strip()}

    def snapshot_path(self) -> Path:
        path = Path(self.snapshot_dir)
        if not path.is_absolute():
            return ROOT / path
        return path

    def user_agent(self) -> str:
        if self.contact_email:
            return f"sibyl ({self.contact_email})"
        return "sibyl"

    def redact(self, text: str) -> str:
        redacted = text
        for secret in (
            self.database_url,
            self.nvd_api_key,
            self.github_token,
            self.contact_email,
            self.zetaris_api_key,
            self.meterless_runtime_token,
        ):
            if secret:
                redacted = redacted.replace(secret, "***")
        return redacted


def load_settings() -> Settings:
    """Load `.env` without overriding variables already set in the process."""
    load_dotenv(ROOT / ".env")
    return Settings(
        database_url=os.environ.get("DATABASE_URL", ""),
        sample_mode=_as_bool(os.environ.get("SAMPLE_MODE"), True),
        contact_email=os.environ.get("CONTACT_EMAIL", "").strip(),
        nvd_api_key=os.environ.get("NVD_API_KEY", "").strip(),
        github_token=os.environ.get("GITHUB_TOKEN", "").strip(),
        disable_sources=os.environ.get("DISABLE_SOURCES", ""),
        snapshot_dir=os.environ.get("SNAPSHOT_DIR", "data/sample/snapshots"),
        zetaris_rest_url=os.environ.get("ZETARIS_REST_URL", "").strip(),
        zetaris_org_id=os.environ.get("ZETARIS_ORG_ID", "1").strip() or "1",
        zetaris_api_key=os.environ.get("ZETARIS_API_KEY", "").strip(),
        meterless_base_url=os.environ.get("METERLESS_BASE_URL", "http://127.0.0.1:8088/v1").strip()
        or "http://127.0.0.1:8088/v1",
        meterless_runtime_token=os.environ.get("METERLESS_RUNTIME_TOKEN", "").strip(),
        meterless_model_fast=os.environ.get("METERLESS_MODEL_FAST", "").strip() or "meterless/fast",
        meterless_model_deep=os.environ.get("METERLESS_MODEL_DEEP", "").strip() or "meterless/deep",
        meterless_model_critic=os.environ.get("METERLESS_MODEL_CRITIC", "").strip() or "meterless/fusion",
        meterless_model_judge=os.environ.get("METERLESS_MODEL_JUDGE", "").strip() or "meterless/fusion",
        meterless_max_tokens=_as_int(os.environ.get("METERLESS_MAX_TOKENS"), 8192),
        run_max_seconds=_as_int(os.environ.get("RUN_MAX_SECONDS"), 600),
        run_max_tokens=_as_int(os.environ.get("RUN_MAX_TOKENS"), 400_000),
        critic_enabled=_as_bool(os.environ.get("CRITIC_ENABLED"), True),
        cdxgen_cmd=os.environ.get("CDXGEN_CMD", "").strip() or "npx --yes @cyclonedx/cdxgen@12.9.0",
        repos_dir=os.environ.get("REPOS_DIR", "").strip() or "var/repos",
        scheduler_enabled=_as_bool(os.environ.get("SIBYL_SCHEDULER"), True),
    )
