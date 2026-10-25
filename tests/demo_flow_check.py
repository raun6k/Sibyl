#!/usr/bin/env python3
"""Click-path through the API: run, resolve, approve, run again, fewer escalations."""

from __future__ import annotations

import sys
from urllib.parse import quote

from fastapi.testclient import TestClient


def main() -> int:
    from sibyl.api.app import app

    with TestClient(app) as client:
        from sibyl.api.app import hub

        if hub is not None:
            hub.hmem.reset()
        first = _run(client)
        needs = first["needs_human"]
        if not needs:
            raise SystemExit("run 1 has no needs-human case")
        target = next((card for card in needs if card.get("package") == "decode-uri-component"), needs[0])
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
            f"/cases/{quote(needs[-1]['case_id'], safe='')}/resolution",
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
        approved = client.post(f"/memory/pending/{pending['id']}/approve")
        if approved.status_code != 200 or not approved.json().get("ok"):
            raise SystemExit(approved.text)
        second = _run(client)
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
        from sibyl.api.app import hub

        if hub is not None:
            hub.hmem.reset()
        print(f"PASS demo flow needs-human {len(needs)} -> {len(second['needs_human'])}")
        return 0


def _run(client: TestClient) -> dict:
    started = client.post("/runs", json={"dataset": "fixtures", "disable_sources": [], "window_days": 14})
    if started.status_code != 202:
        raise SystemExit(started.text)
    run_id = started.json()["run_id"]
    with client.stream("GET", f"/runs/{run_id}/events") as response:
        for line in response.iter_lines():
            text = line.decode() if isinstance(line, bytes) else line
            if '"to": "FAILED"' in text:
                raise SystemExit(text)
            if '"to": "DONE"' in text:
                break
    report = client.get(f"/runs/{run_id}/report")
    if report.status_code != 200:
        raise SystemExit(report.text)
    return report.json()


if __name__ == "__main__":
    sys.exit(main())
