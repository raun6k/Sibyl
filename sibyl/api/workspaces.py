"""Workspace, repository, service and question routes.

A repository sync runs in a background thread, one at a time per
repository. `POST /hooks/push` lets a local git hook or CI ask for a sync
after a push or merge to the tracked branch.
"""

from __future__ import annotations

import re
import shutil
import sys
import threading
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from sibyl.config import ROOT, load_settings
from sibyl.inventory import store
from sibyl.inventory.purls import parse as parse_purl
from sibyl.inventory.schema import DEMO_WORKSPACE
from sibyl.repos.profiler import DATA_CLASSES
from sibyl.repos.source import RepoError, kind_of, remove_checkout

router = APIRouter()
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")


class WorkspaceBody(BaseModel):
    name: str


class RepositoryBody(BaseModel):
    location: str
    branch: str = "main"
    token_env: str = ""
    sync_interval_minutes: int = Field(default=60, ge=5, le=10080)


class RepositoryPatch(BaseModel):
    branch: str | None = None
    token_env: str | None = None
    sync_interval_minutes: int | None = Field(default=None, ge=5, le=10080)


class ServiceBody(BaseModel):
    name: str
    team: str = ""
    internet_facing: bool = False
    criticality: float = Field(default=0.5, ge=0, le=1)
    data_class: str = "internal"
    sbom: dict[str, Any] | None = None
    user: str = ""


class ServicePatch(BaseModel):
    name: str | None = None
    team: str | None = None
    internet_facing: bool | None = None
    criticality: float | None = Field(default=None, ge=0, le=1)
    data_class: str | None = None
    triage_policy: str | None = None
    triage_interval_minutes: int | None = Field(default=None, ge=15, le=43200)
    user: str = ""


class AnswerBody(BaseModel):
    action: str  # confirm, change, dismiss
    value: Any = None
    user: str = ""


def _active():
    from sibyl.api.app import _hub

    return _hub()


def _not_found(exc: Exception) -> HTTPException:
    return HTTPException(status_code=404, detail=str(exc))


def _workspace_or_404(workspace_id: str) -> dict[str, Any]:
    if not store.safe_id(workspace_id):
        raise HTTPException(status_code=404, detail="unknown workspace")
    try:
        return store.get_workspace(workspace_id)
    except store.NotFound as exc:
        raise _not_found(exc) from None


# Workspaces ---------------------------------------------------------------


@router.get("/workspaces")
def list_workspaces() -> dict[str, Any]:
    return {"workspaces": store.list_workspaces()}


@router.post("/workspaces", status_code=201)
def create_workspace(body: WorkspaceBody) -> dict[str, Any]:
    return store.create_workspace(body.name)


@router.post("/workspaces/demo", status_code=201)
def create_demo() -> dict[str, Any]:
    """Load the sample workspace (opt-in). Re-running it restores the sample services."""
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    from seed_db import main as seed_main

    if seed_main([]) != 0:
        raise HTTPException(status_code=500, detail="seeding the demo workspace failed")
    return store.get_workspace(DEMO_WORKSPACE)


@router.patch("/workspaces/{workspace_id}")
def rename_workspace(workspace_id: str, body: WorkspaceBody) -> dict[str, Any]:
    _workspace_or_404(workspace_id)
    return store.rename_workspace(workspace_id, body.name)


@router.delete("/workspaces/{workspace_id}", status_code=204)
def delete_workspace(workspace_id: str) -> None:
    _workspace_or_404(workspace_id)
    active = _active()
    current = active.runs.get(active.current or "") or {}
    if current.get("workspace_id") == workspace_id:
        raise HTTPException(status_code=409, detail="a run is in progress in this workspace")
    settings = load_settings()
    for repo in store.list_repositories(workspace_id):
        remove_checkout(repo, settings)
    store.delete_workspace(workspace_id)
    active.drop_workspace(workspace_id)
    if workspace_id != DEMO_WORKSPACE:
        from sibyl.api.app import hmem_dir

        shutil.rmtree(hmem_dir(workspace_id), ignore_errors=True)


# Repositories -------------------------------------------------------------


@router.get("/workspaces/{workspace_id}/repositories")
def list_repositories(workspace_id: str) -> dict[str, Any]:
    _workspace_or_404(workspace_id)
    active = _active()
    repos = store.list_repositories(workspace_id)
    for repo in repos:
        repo["syncing"] = repo["repo_id"] in active.syncing
    return {"repositories": repos}


@router.post("/workspaces/{workspace_id}/repositories", status_code=201)
def connect_repository(workspace_id: str, body: RepositoryBody) -> dict[str, Any]:
    workspace = _workspace_or_404(workspace_id)
    if workspace["is_demo"]:
        raise HTTPException(status_code=422, detail="the demo workspace uses sample services; create a workspace to connect a repository")
    if body.token_env and not _ENV_NAME.fullmatch(body.token_env):
        raise HTTPException(status_code=422, detail="token_env must be an environment variable name, not the token")
    try:
        kind = kind_of(body.location)
    except RepoError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    repo = store.create_repository(
        workspace_id,
        kind=kind,
        location=body.location.strip(),
        branch=body.branch.strip() or "main",
        token_env=body.token_env,
        sync_interval_minutes=body.sync_interval_minutes,
    )
    start_sync(repo["repo_id"])
    return {**repo, "syncing": True}


@router.get("/repositories/{repo_id}")
def get_repository(repo_id: str) -> dict[str, Any]:
    try:
        repo = store.get_repository(repo_id)
    except store.NotFound as exc:
        raise _not_found(exc) from None
    repo["syncing"] = repo_id in _active().syncing
    repo["syncs"] = store.list_syncs(repo_id=repo_id, limit=10)
    repo["services"] = store.services_for_repo(repo_id)
    return repo


@router.patch("/repositories/{repo_id}")
def update_repository(repo_id: str, body: RepositoryPatch) -> dict[str, Any]:
    if body.token_env and not _ENV_NAME.fullmatch(body.token_env):
        raise HTTPException(status_code=422, detail="token_env must be an environment variable name, not the token")
    try:
        return store.update_repository(repo_id, body.model_dump(exclude_none=True))
    except store.NotFound as exc:
        raise _not_found(exc) from None


@router.delete("/repositories/{repo_id}", status_code=204)
def delete_repository(repo_id: str) -> None:
    try:
        repo = store.get_repository(repo_id)
    except store.NotFound as exc:
        raise _not_found(exc) from None
    if repo_id in _active().syncing:
        raise HTTPException(status_code=409, detail="the repository is syncing")
    remove_checkout(repo, load_settings())
    store.delete_repository(repo_id)


@router.post("/repositories/{repo_id}/sync", status_code=202)
def sync_now(repo_id: str, full: bool = False) -> dict[str, Any]:
    try:
        store.get_repository(repo_id)
    except store.NotFound as exc:
        raise _not_found(exc) from None
    if not start_sync(repo_id, full=full):
        raise HTTPException(status_code=409, detail="the repository is already syncing")
    return {"repo_id": repo_id, "syncing": True}


@router.post("/hooks/push", status_code=202)
def push_hook(repo: str) -> dict[str, Any]:
    """Called by a git hook or CI after a push or merge to the tracked branch."""
    return sync_now(repo)


@router.get("/workspaces/{workspace_id}/syncs")
def list_syncs(workspace_id: str, limit: int = 20) -> dict[str, Any]:
    _workspace_or_404(workspace_id)
    return {"syncs": store.list_syncs(workspace_id=workspace_id, limit=max(1, min(limit, 100)))}


def start_sync(repo_id: str, *, full: bool = False) -> bool:
    active = _active()
    with active.lock:
        if repo_id in active.syncing:
            return False
        active.syncing.add(repo_id)
    threading.Thread(target=_sync, args=(repo_id, full), daemon=True).start()
    return True


def _sync(repo_id: str, full: bool) -> None:
    from sibyl.llm.client import LLMClient
    from sibyl.repos.sync import sync_repository

    active = _active()
    settings = load_settings()
    try:
        repo = store.get_repository(repo_id)
        hmem = active.hmem_for(repo["workspace_id"])
        llm = LLMClient(settings) if settings.meterless_runtime_token else None
        try:
            sync_repository(repo_id, settings, hmem=hmem, llm=llm, force_full=full)
        finally:
            if llm is not None:
                llm.close()
    except Exception as exc:  # recorded on the repository so the UI can show it
        try:
            store.update_repository(repo_id, {"status": "error", "error": settings.redact(str(exc))[:500]})
        except Exception:
            pass
    finally:
        with active.lock:
            active.syncing.discard(repo_id)


# Services -----------------------------------------------------------------


@router.get("/workspaces/{workspace_id}/services")
def list_services(workspace_id: str) -> dict[str, Any]:
    _workspace_or_404(workspace_id)
    return {"services": store.list_services(workspace_id)}


@router.post("/workspaces/{workspace_id}/services", status_code=201)
def add_service(workspace_id: str, body: ServiceBody) -> dict[str, Any]:
    """A service added by hand, with an optional CycloneDX SBOM. Its facts count as confirmed by a person."""
    _workspace_or_404(workspace_id)
    if body.data_class not in DATA_CLASSES:
        raise HTTPException(status_code=422, detail="unknown data_class")
    facts = {"team": body.team, "internet_facing": body.internet_facing, "criticality": body.criticality, "data_class": body.data_class}
    service = store.create_service(workspace_id, body.name, facts=facts)
    if body.sbom is not None:
        components = _sbom_components(body.sbom)
        if not components:
            store.remove_service(service["service_id"])
            raise HTTPException(status_code=422, detail="the SBOM has no components with a package URL")
        store.replace_components(service["service_id"], components, source="uploaded SBOM")
    hmem = _active().hmem_for(workspace_id)
    for name, value in facts.items():
        hmem.record_fact(service["service_id"], name, value, origin="human", user=body.user)
    return store.get_service(service["service_id"])


@router.patch("/services/{service_id}")
def update_service(service_id: str, body: ServicePatch) -> dict[str, Any]:
    try:
        service = store.get_service(service_id)
    except store.NotFound as exc:
        raise _not_found(exc) from None
    if body.data_class is not None and body.data_class not in DATA_CLASSES:
        raise HTTPException(status_code=422, detail="unknown data_class")
    changes = body.model_dump(exclude_none=True, exclude={"user"})
    try:
        updated = store.update_service(service_id, changes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    edited = [name for name in store.FACT_FIELDS if name in changes]
    if edited:
        hmem = _active().hmem_for(service["workspace_id"])
        for name in edited:
            hmem.record_fact(service_id, name, updated[name], origin="human", user=body.user)
        store.close_questions_for(service_id, ["service_fact", "fact_changed"], fields=edited, user=body.user or "you")
    return updated


@router.delete("/services/{service_id}", status_code=204)
def remove_service(service_id: str) -> None:
    try:
        service = store.get_service(service_id)
    except store.NotFound as exc:
        raise _not_found(exc) from None
    store.remove_service(service_id)
    _active().hmem_for(service["workspace_id"]).forget_service(service_id)


def _sbom_components(document: dict[str, Any]):
    found = []
    seen: set[str] = set()

    def walk(items):
        for item in items or []:
            if not isinstance(item, dict):
                continue
            component = parse_purl(str(item.get("purl") or ""), str(item.get("name") or ""), str(item.get("version") or ""))
            if component is not None and component.purl not in seen:
                seen.add(component.purl)
                found.append((component, False, "uploaded SBOM"))
            walk(item.get("components"))

    walk(document.get("components"))
    return found


# Questions ----------------------------------------------------------------


@router.get("/workspaces/{workspace_id}/questions")
def list_questions(workspace_id: str, status: str = "open") -> dict[str, Any]:
    _workspace_or_404(workspace_id)
    if status not in {"open", "answered", "dismissed", "all"}:
        raise HTTPException(status_code=422, detail="status must be open, answered, dismissed or all")
    return {"questions": store.list_questions(workspace_id, status)}


@router.post("/questions/{question_id}/answer")
def answer_question(question_id: str, body: AnswerBody) -> dict[str, Any]:
    try:
        question = store.get_question(question_id)
    except store.NotFound as exc:
        raise _not_found(exc) from None
    if question["status"] != "open":
        raise HTTPException(status_code=409, detail="the question is already closed")
    if body.action not in {"confirm", "change", "dismiss"}:
        raise HTTPException(status_code=422, detail="action must be confirm, change or dismiss")
    kind = question["kind"]
    service_id = question.get("service_id")
    user = body.user or "you"
    answer: dict[str, Any] = {"action": body.action}
    if kind in {"service_fact", "fact_changed"} and body.action != "dismiss" and service_id:
        field = question["field"]
        value = question.get("proposed") if body.action == "confirm" else body.value
        value = _fact_value(field, value)
        store.update_service(service_id, {field: value})
        _active().hmem_for(question["workspace_id"]).record_fact(
            service_id, field, value, origin="human", user=user, evidence=question.get("evidence") or []
        )
        answer["value"] = value
    elif kind == "service_found" and body.action == "dismiss" and service_id:
        store.remove_service(service_id)
        _active().hmem_for(question["workspace_id"]).forget_service(service_id)
        answer["removed"] = True
    elif kind == "service_gone" and body.action == "confirm" and service_id:
        store.remove_service(service_id)
        _active().hmem_for(question["workspace_id"]).forget_service(service_id)
        answer["removed"] = True
    try:
        status = "dismissed" if body.action == "dismiss" else "answered"
        return store.close_question(question_id, status=status, answer=answer, user=user)
    except store.NotFound:
        # Removing a service also removes its questions.
        return {**question, "status": "answered", "answer": answer}


def _fact_value(field: str, value: Any) -> Any:
    if field == "internet_facing":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"true", "yes", "1", "internet-facing"}
    if field == "criticality":
        try:
            number = float(value)
        except (TypeError, ValueError):
            raise HTTPException(status_code=422, detail="criticality must be a number from 0 to 1") from None
        if not 0 <= number <= 1:
            raise HTTPException(status_code=422, detail="criticality must be a number from 0 to 1")
        return number
    if field == "data_class":
        text = str(value or "").strip().lower()
        if text not in DATA_CLASSES:
            raise HTTPException(status_code=422, detail="unknown data_class")
        return text
    return str(value or "").strip()[:80]
