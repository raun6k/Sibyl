"""Where a repository's code comes from: a git URL Sibyl mirrors, or a local folder.

Sibyl only reads. A git URL is cloned into `REPOS_DIR/<repo_id>` and moved to
the branch tip on every sync; hooks never run and submodules are not
followed. A token, when the repository names one, is read from the
environment variable it names and passed to git through `GIT_CONFIG_*`, so
it is never written to `.git/config` or shown in a process list.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sibyl.config import ROOT, Settings

_SHA = re.compile(r"^[0-9a-f]{40}$")
GIT_TIMEOUT = 600


class RepoError(RuntimeError):
    pass


@dataclass(frozen=True)
class Change:
    status: str  # A, M, D, R (renames are split into D + A by `paths`)
    path: str


class RepoSource(Protocol):
    def sync(self) -> str:
        """Bring the checkout to the branch tip. Returns the commit sha, or "" when there is none."""

    def root(self) -> Path:
        """The directory to scan."""

    def changes(self, old: str, new: str) -> list[Change] | None:
        """Paths that differ between two commits, or None when they can't be compared."""

    def remote_head(self) -> str:
        """The branch tip without fetching objects, for cheap polling. "" when unknown."""


def kind_of(location: str) -> str:
    """`local` for an existing directory, `git` for a URL."""
    text = location.strip()
    if text.startswith(("https://", "http://", "ssh://", "git@", "file://")):
        return "git"
    if Path(text).expanduser().is_dir():
        return "local"
    raise RepoError("location must be a git URL (https, ssh) or an existing local folder")


def open_source(repo: dict, settings: Settings) -> RepoSource:
    if repo["kind"] == "local":
        return LocalRepo(Path(repo["location"]).expanduser(), repo.get("branch") or "")
    return GitRepo(
        url=repo["location"],
        branch=repo.get("branch") or "main",
        directory=_repos_dir(settings) / repo["repo_id"],
        token=os.environ.get(repo.get("token_env") or "", "") if repo.get("token_env") else "",
    )


def remove_checkout(repo: dict, settings: Settings) -> None:
    if repo.get("kind") != "git":
        return
    target = _repos_dir(settings) / repo["repo_id"]
    if target.is_dir() and _repos_dir(settings) in target.resolve().parents:
        shutil.rmtree(target, ignore_errors=True)


def _repos_dir(settings: Settings) -> Path:
    path = Path(settings.repos_dir)
    return (path if path.is_absolute() else ROOT / path).resolve()


def _git(args: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None, timeout: int = GIT_TIMEOUT) -> str:
    base = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never", "-c", "submodule.recurse=false"]
    merged = os.environ.copy()
    merged["GIT_TERMINAL_PROMPT"] = "0"
    merged.update(env or {})
    try:
        done = subprocess.run(
            base + args,
            cwd=str(cwd) if cwd else None,
            env=merged,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RepoError(f"git {args[0]} timed out") from exc
    except FileNotFoundError as exc:
        raise RepoError("git is not installed") from exc
    if done.returncode != 0:
        detail = " ".join((done.stderr or done.stdout).split())[:300]
        raise RepoError(f"git {args[0]} failed: {detail}")
    return done.stdout


def _parse_changes(text: str) -> list[Change]:
    found: list[Change] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0]:
            continue
        status = parts[0][0]
        if status == "R" and len(parts) >= 3:
            found.append(Change("D", parts[1]))
            found.append(Change("A", parts[2]))
        elif status == "C" and len(parts) >= 3:
            found.append(Change("A", parts[2]))
        else:
            found.append(Change(status, parts[1]))
    return found


class GitRepo:
    def __init__(self, *, url: str, branch: str, directory: Path, token: str = "") -> None:
        self.url = url
        self.branch = branch
        self.directory = directory
        self._env: dict[str, str] = {}
        if token:
            basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
            self._env = {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.extraHeader",
                "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
            }

    def root(self) -> Path:
        return self.directory

    def sync(self) -> str:
        if not (self.directory / ".git").is_dir():
            self.directory.parent.mkdir(parents=True, exist_ok=True)
            if self.directory.exists():
                shutil.rmtree(self.directory)
            _git(
                [
                    "clone",
                    "--filter=blob:none",
                    "--no-tags",
                    "--single-branch",
                    "--branch",
                    self.branch,
                    "--",
                    self.url,
                    str(self.directory),
                ],
                env=self._env,
            )
        else:
            _git(["fetch", "--filter=blob:none", "--no-tags", "origin", self.branch], cwd=self.directory, env=self._env)
            _git(["reset", "--hard", "FETCH_HEAD"], cwd=self.directory)
        return _git(["rev-parse", "HEAD"], cwd=self.directory).strip()

    def changes(self, old: str, new: str) -> list[Change] | None:
        if not (_SHA.fullmatch(old or "") and _SHA.fullmatch(new or "")):
            return None
        try:
            # The old commit may be gone after a force-push; then the caller rescans everything.
            _git(["cat-file", "-e", f"{old}^{{commit}}"], cwd=self.directory, env=self._env)
            return _parse_changes(_git(["diff", "--name-status", "-M", old, new], cwd=self.directory, env=self._env))
        except RepoError:
            return None

    def remote_head(self) -> str:
        try:
            out = _git(["ls-remote", self.url, f"refs/heads/{self.branch}"], env=self._env, timeout=60)
        except RepoError:
            return ""
        first = out.split()
        return first[0] if first and _SHA.fullmatch(first[0]) else ""


class LocalRepo:
    """A folder on this machine, read in place. Incremental only when it is a git work tree."""

    def __init__(self, path: Path, branch: str = "") -> None:
        self.path = path
        self.branch = branch

    def root(self) -> Path:
        return self.path

    def _is_git(self) -> bool:
        return (self.path / ".git").exists()

    def sync(self) -> str:
        if not self.path.is_dir():
            raise RepoError(f"{self.path} is not a folder")
        if not self._is_git():
            return ""
        return _git(["rev-parse", "HEAD"], cwd=self.path).strip()

    def changes(self, old: str, new: str) -> list[Change] | None:
        if not self._is_git() or not (_SHA.fullmatch(old or "") and _SHA.fullmatch(new or "")):
            return None
        try:
            _git(["cat-file", "-e", f"{old}^{{commit}}"], cwd=self.path)
            return _parse_changes(_git(["diff", "--name-status", "-M", old, new], cwd=self.path))
        except RepoError:
            return None

    def remote_head(self) -> str:
        try:
            return self.sync()
        except RepoError:
            return ""
