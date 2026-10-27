"""Sync one repository into the inventory.

The first sync scans the whole tree. Later syncs read `git diff` between the
last scanned commit and the new tip and only:

- re-scan a service whose manifest changed (a component diff is recorded),
- re-profile a service whose Dockerfile, compose, Kubernetes or CODEOWNERS changed,
- open a "new service" question for a new manifest directory,
- open a "service gone" question when a service's directory disappeared.

Facts a person confirmed live in H-MEM and outrank a later derivation: the
derived value is stored below the human one and the service keeps the
human value. Each sync ends with the Zetaris data-quality rules.

With a World Model, every service whose components were written gets its
`uses` edges brought up to date, valid from the commit time, so a new
version closes the old edge.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from sibyl.config import Settings
from sibyl.inventory import store
from sibyl.inventory.store import FACT_FIELDS
from sibyl.repos import profiler
from sibyl.repos.scanner import Candidate, FoundComponent, ScanResult, is_manifest, scan, service_dir, skipped_path
from sibyl.repos.source import Change, RepoError, RepoSource, open_source

FIELD_LABEL = {"internet_facing": "exposure", "team": "owning team", "criticality": "criticality", "data_class": "data class"}
FACT_FILE_NAMES = {"CODEOWNERS", "Procfile", "fly.toml", "app.yaml", "serverless.yml", ".env.example", ".env.sample"}
FACT_DIRS = {"k8s", "kubernetes", "deploy", "deployment", "helm", "charts", "manifests", "infra", ".github"}

Scanner = Callable[[Path, Settings, set[str] | None], ScanResult]


@dataclass
class Plan:
    mode: str  # full, incremental, up_to_date
    rescan: set[str] = field(default_factory=set)
    reprofile: set[str] = field(default_factory=set)
    new_dirs: set[str] = field(default_factory=set)
    gone: set[str] = field(default_factory=set)


def plan_changes(changes: list[Change] | None, known_paths: set[str]) -> Plan:
    """What an incremental sync must do, from the changed paths and the known service directories."""
    if changes is None:
        return Plan(mode="full")
    result = Plan(mode="incremental")
    for change in changes:
        path = change.path
        if skipped_path(path):
            continue
        name = PurePosixPath(path).name
        owner = _owning_service(path, known_paths)
        if is_manifest(path):
            directory = service_dir(path)
            if directory in known_paths:
                result.rescan.add(directory)
            elif change.status != "D":
                result.new_dirs.add(directory)
        elif _fact_file(path, name):
            if owner is not None and _directly_under(path, owner):
                result.reprofile.add(owner)
            else:
                # Root CODEOWNERS or a shared deploy folder can change any service's facts.
                result.reprofile.update(known_paths)
        if change.status == "D" and is_manifest(path) and service_dir(path) in known_paths:
            result.gone.add(service_dir(path))
    return result


def _owning_service(path: str, known: set[str]) -> str | None:
    best: str | None = None
    for directory in known:
        if directory == "" or path.startswith(directory.rstrip("/") + "/"):
            if best is None or len(directory) > len(best):
                best = directory
    return best


def _directly_under(path: str, directory: str) -> bool:
    return directory != "" and path.startswith(directory.rstrip("/") + "/")


def _fact_file(path: str, name: str) -> bool:
    if name.startswith("Dockerfile") or "compose" in name and name.endswith((".yml", ".yaml")):
        return True
    if name in FACT_FILE_NAMES:
        return True
    parts = {part.lower() for part in PurePosixPath(path).parts[:-1]}
    return bool(parts & FACT_DIRS) and name.endswith((".yml", ".yaml"))


def sync_repository(
    repo_id: str,
    settings: Settings,
    *,
    hmem: Any | None = None,
    llm: Any | None = None,
    force_full: bool = False,
    scanner: Scanner | None = None,
    source: RepoSource | None = None,
    quality: Callable[[str, Settings], list[dict[str, Any]]] | None = None,
    world: Any | None = None,
) -> dict[str, Any]:
    """Run one sync and record it in `inventory.repo_syncs`. Returns the summary."""
    repo = store.get_repository(repo_id, settings)
    workspace_id = repo["workspace_id"]
    sync_id = store.start_sync(repo_id, workspace_id, repo.get("last_scanned_sha"), "full" if force_full else "pending", settings)
    store.update_repository(repo_id, {"status": "syncing", "error": ""}, settings)
    started = time.perf_counter()
    summary: dict[str, Any] = {"services": {}, "new_services": [], "questions": 0, "skipped": [], "limits": [], "not_covered": {}}
    head = ""
    plan = Plan(mode="full")
    try:
        origin = source or open_source(repo, settings)
        head = origin.sync()
        root = origin.root()
        last = repo.get("last_scanned_sha") or ""
        known = {service["path"]: service for service in store.services_for_repo(repo_id, settings)}
        if not force_full and head and last == head and known:
            plan = Plan(mode="up_to_date")
        elif force_full or not last or not known:
            plan = Plan(mode="full")
        else:
            plan = plan_changes(origin.changes(last, head), set(known))
        run_scan = scanner or (lambda path, active, only: scan(path, active, only=only))
        if plan.mode == "full":
            result = run_scan(root, settings, None)
            _apply_full(repo, result, known, root, head, settings, hmem, llm, summary)
        elif plan.mode == "incremental":
            targets = plan.rescan | plan.new_dirs
            result = run_scan(root, settings, targets) if targets else ScanResult(candidates=[])
            _apply_incremental(repo, plan, result, known, root, head, settings, hmem, llm, summary)
        summary["mode"] = plan.mode
        if world is not None and plan.mode != "up_to_date":
            summary["edges"] = _edges(world, summary, getattr(origin, "commit_time", lambda _sha: "")(head) if head else "", settings)
        if plan.mode != "up_to_date":
            summary["quality"] = _quality(workspace_id, settings, quality, repo_id, summary)
        summary["seconds"] = round(time.perf_counter() - started, 1)
        store.update_repository(
            repo_id,
            {"status": "ready", "last_scanned_sha": head or None, "last_synced_at": store._now(), "error": ""},
            settings,
        )
        store.finish_sync(sync_id, status="done", to_sha=head or None, mode=plan.mode, summary=summary, settings=settings)
        return {"sync_id": sync_id, **summary}
    except (RepoError, RuntimeError, OSError, ValueError) as exc:
        message = settings.redact(str(exc))[:500]
        store.update_repository(repo_id, {"status": "error", "error": message}, settings)
        store.finish_sync(sync_id, status="failed", to_sha=head or None, mode=plan.mode, summary=summary, error=message, settings=settings)
        return {"sync_id": sync_id, "error": message, **summary}


def _edges(world: Any, summary: dict[str, Any], at: str, settings: Settings) -> dict[str, int]:
    from sibyl.inventory.edges import sync_service_edges

    totals = {"opened": 0, "closed": 0}
    for service_id in summary["services"]:
        counts = sync_service_edges(world, service_id, at=at, settings=settings)
        totals["opened"] += counts["opened"]
        totals["closed"] += counts["closed"]
    return totals


def _apply_full(repo, result: ScanResult, known: dict[str, dict], root: Path, head: str, settings, hmem, llm, summary) -> None:
    summary["skipped"] = result.skipped
    summary["limits"] = result.limits
    summary["not_covered"] = result.not_covered
    found = {candidate.path for candidate in result.candidates}
    first = not known
    for candidate in result.candidates:
        service = known.get(candidate.path)
        if service is None:
            service = _new_service(repo, candidate, root, head, settings, hmem, llm, summary, ask_keep=not first)
        else:
            _replace(service, candidate, head, settings, summary)
            _profile(repo, service, candidate, root, settings, hmem, llm, summary, only_changed=True)
    for path, service in known.items():
        if path not in found:
            _ask_gone(repo, service, settings, summary)


def _apply_incremental(repo, plan: Plan, result: ScanResult, known: dict[str, dict], root: Path, head: str, settings, hmem, llm, summary) -> None:
    summary["skipped"] = result.skipped
    summary["limits"] = result.limits
    summary["not_covered"] = result.not_covered
    by_path = {candidate.path: candidate for candidate in result.candidates}
    for path in sorted(plan.rescan):
        if path in plan.gone and path not in by_path:
            continue
        candidate = by_path.get(path)
        if candidate is not None:
            _replace(known[path], candidate, head, settings, summary)
    for path in sorted(plan.new_dirs):
        candidate = by_path.get(path)
        if candidate is not None and path not in known:
            _new_service(repo, candidate, root, head, settings, hmem, llm, summary, ask_keep=True)
    for path in sorted(plan.reprofile):
        if path in known and path not in plan.gone:
            candidate = by_path.get(path) or Candidate(path=path, name=known[path]["name"])
            _profile(repo, known[path], candidate, root, settings, hmem, llm, summary, only_changed=True)
    for path in sorted(plan.gone):
        if path in known and path not in by_path:
            _ask_gone(repo, known[path], settings, summary)


def _new_service(repo, candidate: Candidate, root: Path, head: str, settings, hmem, llm, summary, *, ask_keep: bool) -> dict:
    proposal = profiler.propose(root, candidate, llm)
    facts = {name: proposal.facts[name]["value"] for name in FACT_FIELDS}
    service = store.create_service(repo["workspace_id"], candidate.name, repo_id=repo["repo_id"], path=candidate.path, facts=facts, settings=settings)
    diff = store.replace_components(
        service["service_id"],
        [(item.component, item.direct, item.source_file) for item in candidate.components],
        source=", ".join(candidate.manifests),
        commit_sha=head or None,
        settings=settings,
    )
    summary["new_services"].append({"service_id": service["service_id"], "path": candidate.path, "components": len(candidate.components)})
    summary["services"][service["service_id"]] = {"added": len(diff.added), "removed": 0, "changed": 0}
    if ask_keep:
        store.add_question(
            repo["workspace_id"],
            kind="service_found",
            prompt=f"Sibyl found a new service at {profiler.path_label(candidate.path)} in {repo['repo_id']}. Keep it?",
            service_id=service["service_id"],
            repo_id=repo["repo_id"],
            proposed={"keep": True, "manifests": candidate.manifests},
            confidence=0.8,
            settings=settings,
        )
        summary["questions"] += 1
    _record(repo, service, proposal, settings, hmem, summary, only_changed=False)
    return service


def _replace(service: dict, candidate: Candidate, head: str, settings, summary) -> None:
    diff = store.replace_components(
        service["service_id"],
        [(item.component, item.direct, item.source_file) for item in candidate.components],
        source=", ".join(candidate.manifests),
        commit_sha=head or None,
        settings=settings,
    )
    summary["services"][service["service_id"]] = {
        "added": len(diff.added),
        "removed": len(diff.removed),
        "changed": len(diff.changed),
        "diff": {key: values[:20] for key, values in diff.as_dict().items()},
    }


def _profile(repo, service: dict, candidate: Candidate, root: Path, settings, hmem, llm, summary, *, only_changed: bool) -> None:
    if not candidate.components:
        # A re-profile without a re-scan keeps the dependency signals from the stored components.
        candidate = Candidate(
            path=candidate.path,
            name=candidate.name,
            components=[FoundComponent(item, direct, source) for item, direct, source in store.components_for(service["service_id"], settings)],
        )
    proposal = profiler.propose(root, candidate, llm)
    _record(repo, service, proposal, settings, hmem, summary, only_changed=only_changed)


def _record(repo, service: dict, proposal: profiler.Proposal, settings, hmem, summary, *, only_changed: bool) -> None:
    """Store derived facts in H-MEM and ask about each one a person has not settled."""
    evidence = {item.id: item.as_dict() for item in proposal.evidence}
    updates: dict[str, Any] = {}
    for name in FACT_FIELDS:
        guess = proposal.facts[name]
        cited = [evidence[ref] for ref in guess.get("evidence", []) if ref in evidence]
        human = None
        overruled = False
        if hmem is not None:
            try:
                stored = hmem.record_fact(
                    service["service_id"],
                    name,
                    guess["value"],
                    origin="derived",
                    confidence=float(guess["confidence"]),
                    evidence=cited,
                )
                current = stored.get("current") or {}
                if current.get("origin") == "human":
                    human = current
                    overruled = bool(stored.get("overruled"))
            except RuntimeError:
                hmem = None
        if human is not None:
            updates[name] = human.get("value")
            if overruled:
                store.add_question(
                    repo["workspace_id"],
                    kind="fact_changed",
                    field=name,
                    prompt=(
                        f"The code now points to a different {FIELD_LABEL[name]} for {service['name']}: "
                        f"{guess['value']!r}. You said {human.get('value')!r}. Change it?"
                    ),
                    service_id=service["service_id"],
                    repo_id=repo["repo_id"],
                    proposed=guess["value"],
                    evidence=cited,
                    confidence=float(guess["confidence"]),
                    settings=settings,
                )
                summary["questions"] += 1
            continue
        if only_changed and _same(service.get(name), guess["value"]):
            continue
        updates[name] = guess["value"]
        store.add_question(
            repo["workspace_id"],
            kind="service_fact",
            field=name,
            prompt=profiler.question_text(name, service["name"], guess["value"]),
            service_id=service["service_id"],
            repo_id=repo["repo_id"],
            proposed=guess["value"],
            evidence=cited + ([{"note": guess.get("reason", ""), "by": proposal.by}] if guess.get("reason") else []),
            confidence=float(guess["confidence"]),
            settings=settings,
        )
        summary["questions"] += 1
    if updates:
        store.update_service(service["service_id"], updates, settings)
    if proposal.dropped_lines:
        summary.setdefault("quarantined_lines", 0)
        summary["quarantined_lines"] += proposal.dropped_lines


def _ask_gone(repo, service: dict, settings, summary) -> None:
    store.add_question(
        repo["workspace_id"],
        kind="service_gone",
        prompt=f"{service['name']} ({profiler.path_label(service['path'])}) no longer has a manifest in {repo['repo_id']}. Remove it?",
        service_id=service["service_id"],
        repo_id=repo["repo_id"],
        proposed={"remove": True},
        confidence=0.8,
        settings=settings,
    )
    summary["questions"] += 1


def _quality(workspace_id: str, settings: Settings, runner, repo_id: str, summary) -> list[dict[str, Any]]:
    try:
        if runner is None:
            from sibyl.inventory.usl import run_quality

            runner = run_quality
        results = runner(workspace_id, settings)
    except Exception as exc:  # Zetaris down must not lose the sync itself
        return [{"rule": "zetaris", "error": settings.redact(str(exc))[:300], "invalid": 0, "examples": []}]
    for entry in results:
        if entry.get("invalid"):
            store.add_question(
                workspace_id,
                kind="data_quality",
                field=entry["rule"],
                prompt=f"{entry['invalid']} {entry['table']} rows fail the check that {entry['meaning']}.",
                repo_id=repo_id,
                proposed=None,
                evidence=[{"text": example} for example in entry.get("examples", [])],
                confidence=1.0,
                settings=settings,
            )
            summary["questions"] += 1
    return results


def _same(current: Any, proposed: Any) -> bool:
    if isinstance(proposed, bool):
        truthy = current if isinstance(current, bool) else str(current).strip().lower() in {"true", "t", "1"}
        return truthy == proposed
    if isinstance(proposed, float):
        try:
            return abs(float(current) - proposed) < 1e-6
        except (TypeError, ValueError):
            return False
    return str(current or "") == str(proposed or "")
