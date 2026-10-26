"""A local git repository synced into a throwaway workspace: full scan, then a diff-based sync.

Uses Postgres and git; the scanner is a stub, so cdxgen and Zetaris are not needed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sibyl.config import load_settings
from sibyl.engines.hmem import HmemClient
from sibyl.inventory import store
from sibyl.inventory.purls import parse
from sibyl.repos.scanner import Candidate, FoundComponent, ScanResult, is_manifest, service_dir
from sibyl.repos.sync import sync_repository

pytestmark = pytest.mark.live


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false", *args], cwd=root, check=True, capture_output=True)


def _stub_scanner(root: Path, settings, only):
    """Reads `deps.txt`-style lockfiles: each line of a requirements.txt is `name==version`."""
    found: dict[str, Candidate] = {}
    for path in sorted(root.rglob("requirements.txt")):
        relative = str(path.relative_to(root))
        directory = service_dir(relative)
        if only is not None and directory not in only:
            continue
        candidate = found.setdefault(directory, Candidate(path=directory, name=Path(directory).name or root.name, manifests=[relative]))
        for line in path.read_text().splitlines():
            if "==" in line:
                name, version = line.split("==")
                candidate.components.append(FoundComponent(parse(f"pkg:pypi/{name}@{version}"), True, relative))
    assert all(is_manifest(item) for candidate in found.values() for item in candidate.manifests)
    return ScanResult(candidates=list(found.values()))


def test_full_then_incremental_sync(tmp_path: Path):
    settings = load_settings()
    store.ensure(settings)
    repo_dir = tmp_path / "repo"
    (repo_dir / "services" / "api").mkdir(parents=True)
    (repo_dir / "services" / "api" / "requirements.txt").write_text("django==4.2.3\nrequests==2.31.0\n")
    (repo_dir / "services" / "api" / "Dockerfile").write_text("FROM python:3.12\nEXPOSE 8000\n")
    _git(repo_dir, "init", "-q", "-b", "main")
    _git(repo_dir, "add", "-A")
    _git(repo_dir, "commit", "-qm", "one")
    workspace = store.create_workspace("Sync test")
    try:
        repo = store.create_repository(workspace["workspace_id"], kind="local", location=str(repo_dir))
        with HmemClient(tmp_path / "hmem") as hmem:
            first = sync_repository(repo["repo_id"], settings, hmem=hmem, scanner=_stub_scanner, quality=lambda ws, s: [])
            assert "error" not in first, first
            assert first["mode"] == "full"
            services = store.list_services(workspace["workspace_id"])
            assert [service["path"] for service in services] == ["services/api"]
            api = services[0]
            assert api["components"] == 2
            questions = store.list_questions(workspace["workspace_id"])
            assert {question["field"] for question in questions if question["kind"] == "service_fact"} == {
                "internet_facing",
                "team",
                "criticality",
                "data_class",
            }
            # The person says it is internet-facing; a later derivation must not undo that.
            hmem.record_fact(api["service_id"], "internet_facing", True, origin="human", user="you")
            store.update_service(api["service_id"], {"internet_facing": True})

            (repo_dir / "services" / "api" / "requirements.txt").write_text("django==4.2.11\n")
            (repo_dir / "services" / "worker").mkdir()
            (repo_dir / "services" / "worker" / "requirements.txt").write_text("celery==5.3.0\n")
            _git(repo_dir, "add", "-A")
            _git(repo_dir, "commit", "-qm", "two")
            second = sync_repository(repo["repo_id"], settings, hmem=hmem, scanner=_stub_scanner, quality=lambda ws, s: [])
            assert second["mode"] == "incremental", second
            change = second["services"][api["service_id"]]
            assert change["changed"] == 1 and change["removed"] == 1
            assert [item["path"] for item in second["new_services"]] == ["services/worker"]
            kinds = {question["kind"] for question in store.list_questions(workspace["workspace_id"])}
            assert "service_found" in kinds
            assert store.get_service(api["service_id"])["internet_facing"] is True

            third = sync_repository(repo["repo_id"], settings, hmem=hmem, scanner=_stub_scanner, quality=lambda ws, s: [])
            assert third["mode"] == "up_to_date"
    finally:
        store.delete_workspace(workspace["workspace_id"])
