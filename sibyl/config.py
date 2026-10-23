"""Runtime settings loaded from the environment and the repo `.env`.

Secrets stay out of logs: the database URL, the NVD key, and the GitHub token
are excluded from the model repr.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field

ROOT = Path(__file__).resolve().parents[1]


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
        for secret in (self.database_url, self.nvd_api_key, self.github_token, self.contact_email):
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
    )
