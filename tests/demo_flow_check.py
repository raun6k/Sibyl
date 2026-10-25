#!/usr/bin/env python3
"""Click-path through the API: run, resolve, approve, run again, fewer escalations."""

from __future__ import annotations

import json
import sys
from urllib.parse import quote

from fastapi.testclient import TestClient


def main() -> int:
    from sibyl.api.app import app

    with TestClient(app) as client:
        from sibyl.api.app import hub

        if hub is not None:
            hub.hmem.reset()
        first, first_events = _run(client)
        needs = first["needs_human"]
        if not needs:
            raise SystemExit("run 1 has no needs-human case")
        target = next(card for card in needs if card.get("package") == "decode-uri-component")
        pypi = next(card for card in needs if card.get("package") == "djangorestframework")
        npm = next(
            card
            for card in needs
            if _ecosystem(card) == "npm" and card.get("case_id") != target["case_id"]
        )
        npm_before = npm.get("confidence")
        resolved = client.post(
            f"/cases/{quote(target['case_id'], safe='')}/resolution",
            json={
                "decision": "affected",
                "note": "Remember this case for the next run.",
                "user": "priya",
                "remember": True,
                "scope": "this_case",
            },
        )
        if resolved.status_code != 200:
            raise SystemExit(resolved.text)
        pending_body = client.post(
            f"/cases/{quote(pypi['case_id'], safe='')}/resolution",
            json={
                "decision": "affected",
                "note": "Raise trust in the text source.",
                "user": "priya",
                "remember": True,
                "scope": "adjust_trust",
            },
        )
        pending = (pending_body.json() or {}).get("pending") or {}
        if not pending.get("id"):
            raise SystemExit(f"no pending change: {pending_body.text}")
        if pending.get("ecosystem") != "pypi" or pending.get("source") != "cna":
            raise SystemExit(f"trust scope {pending}")
        if not pending.get("case_id"):
            raise SystemExit(f"trust change has no case: {pending}")
        approved = client.post(f"/memory/pending/{pending['id']}/approve")
        if approved.status_code != 200 or not approved.json().get("ok"):
            raise SystemExit(approved.text)
        second, _second_events = _run(client)
        if len(second["needs_human"]) >= len(needs):
            raise SystemExit(f"needs-human {len(needs)} -> {len(second['needs_human'])}")
        remembered = [
            card
            for branch in ("ranked", "closed", "needs_human")
            for card in second.get(branch) or []
            if card.get("case_id") == target["case_id"]
        ]
        if not remembered or remembered[0].get("resolution") != "memory":
            raise SystemExit(f"resolution {remembered}")
        npm_after = [
            card
            for branch in ("ranked", "closed", "needs_human")
            for card in second.get(branch) or []
            if card.get("case_id") == npm["case_id"]
        ]
        if not npm_after or npm_after[0].get("confidence") != npm_before:
            raise SystemExit(f"pypi trust changed npm confidence {npm_before} -> {npm_after}")
        calls = _llm_events(first_events)
        if not calls:
            raise SystemExit("fixtures run wrote no llm events")
        for event in calls:
            payload = event.get("payload") or {}
            if not payload.get("routed_model") and not payload.get("error_code"):
                raise SystemExit(f"llm event missing routed model and error code: {payload}")
        if len(calls) != len((first.get("receipts") or {}).get("llm") or []):
            raise SystemExit(
                f"llm events {len(calls)} receipts {len((first.get('receipts') or {}).get('llm') or [])}"
            )
        from sibyl.api.app import hub

        if hub is not None:
            hub.hmem.reset()
        print(f"PASS demo flow needs-human {len(needs)} -> {len(second['needs_human'])}")
        return 0


def _run(client: TestClient) -> tuple[dict, list[dict]]:
    started = client.post("/runs", json={"dataset": "fixtures", "disable_sources": [], "window_days": 14})
    if started.status_code != 202:
        raise SystemExit(started.text)
    run_id = started.json()["run_id"]
    events: list[dict] = []
    with client.stream("GET", f"/runs/{run_id}/events") as response:
        for line in response.iter_lines():
            text = line.decode() if isinstance(line, bytes) else line
            if not text.startswith("data:"):
                continue
            event = json.loads(text[5:].strip())
            events.append(event)
            payload = event.get("payload") or {}
            if event.get("type") == "state" and payload.get("to") == "FAILED":
                raise SystemExit(text)
            if event.get("type") == "state" and payload.get("to") == "DONE":
                break
    report = client.get(f"/runs/{run_id}/report")
    if report.status_code != 200:
        raise SystemExit(report.text)
    return report.json(), events


def _llm_events(events: list[dict]) -> list[dict]:
    return [event for event in events if event.get("type") == "llm_call"]


def _ecosystem(card: dict) -> str:
    named = str(card.get("ecosystem") or "").strip().lower()
    if named and named != "*":
        return named
    case_id = str(card.get("case_id") or "")
    marker = "pkg:"
    start = case_id.find(marker)
    if start < 0:
        return "*"
    return case_id[start + len(marker) :].split("/", 1)[0].lower() or "*"


if __name__ == "__main__":
    sys.exit(main())
