"""World Model persistence, inventory edges, the read path and incremental triage."""

from __future__ import annotations

import uuid

from sibyl.agents.reporter import to_markdown
from sibyl.config import load_settings
from sibyl.engines.messages import Claim, Placement, RunClosed, RunOpened
from sibyl.engines.world_model import WorldModelClient, drop_namespace
from sibyl.inventory.edges import apply_edges
from sibyl.inventory.purls import purl_slot
from sibyl.orchestrator.log import RunLog
from sibyl.orchestrator.run import Bundle, run_triage

AXIOS = "case:internal-admin:pkg:npm/axios@0.21.4:CVE-2023-45857"


def _axios(fixed: str = "0.28.0") -> Bundle:
    rows = [
        {
            "service_id": "internal-admin",
            "purl": "pkg:npm/axios@0.21.4",
            "package": "axios",
            "version": "0.21.4",
            "ecosystem": "npm",
            "record_id": f"{source}:GHSA-wf5p-g6vw-rhxx",
            "source": source,
            "record_status": "active",
            "vuln_id": "GHSA-wf5p-g6vw-rhxx",
            "cve_id": "CVE-2023-45857",
            "range_type": "SEMVER",
            "introduced": "0.8.1",
            "fixed": fixed,
            "last_affected": "",
            "raw_range": "",
            "epss_percentile": "0.4",
        }
        for source in ("osv", "ghsa")
    ]
    return Bundle(
        case_id=AXIOS,
        rows=rows,
        package="axios",
        version="0.21.4",
        vuln_id="CVE-2023-45857",
        ecosystem="npm",
        purl="pkg:npm/axios@0.21.4",
        epss_percentile=0.4,
        cvss=6.5,
        cvss_source="cna",
    )


def _run(bundles, world, **options):
    log = RunLog(load_settings())
    try:
        report = run_triage(bundles, llm=None, log=log, world=world, precollected=True, **options)
        events = log.events()
    finally:
        log.delete()
    return report, events


def test_persistent_world_replays_claims_runs_and_edges():
    namespace = f"test-{uuid.uuid4().hex[:8]}"
    claim = Claim(case_id=AXIOS, source="osv", field="affected_range", value=[{"fixed": "1"}], raw_ref="osv:1", retrieved_at="", source_status="active")
    try:
        with WorldModelClient(namespace, persist=True) as world:
            assert world.claim(claim).changed
            changed = claim.model_copy(update={"value": [{"fixed": "2"}]})
            assert world.claim(changed).changed
            # A value that comes back after a change is a change, not a duplicate.
            assert world.claim(claim).changed
            apply_edges(world, "internal-admin", ["pkg:npm/axios@0.21.4", "pkg:npm/lodash@4.17.20"], at="2026-10-01T00:00:00+00:00", source="repo_sync")
            apply_edges(world, "internal-admin", ["pkg:npm/axios@1.7.4"], at="2026-10-20T00:00:00+00:00", source="repo_sync")
            world.write(
                [
                    ("run_opened", RunOpened(run_id="r1")),
                    ("placement", Placement(run_id="r1", case_id=AXIOS, placement="ranked", card={"case_id": AXIOS, "verdict": "affected", "score": 3.0})),
                    ("run_closed", RunClosed(run_id="r1", state="DONE")),
                ]
            )
        with WorldModelClient(namespace, persist=True) as world:
            assert world.replayed > 0
            assert world.claim(claim).changed is False
            now = {edge["to"] for edge in world.edges("service:internal-admin", via="uses")}
            assert now == {"component:pkg:npm/axios@1.7.4"}
            then = {edge["to"] for edge in world.edges("service:internal-admin", via="uses", at="2026-10-05T00:00:00+00:00")}
            assert then == {"component:pkg:npm/axios@0.21.4", "component:pkg:npm/lodash@4.17.20"}
            assert world.report("r1")["ranked"][0]["verdict"] == "affected"
            assert world.current_cases()[0]["case_id"] == AXIOS
            assert world.case(AXIOS, "r2")["prior"]["run_id"] == "r1"
    finally:
        drop_namespace(namespace)


def test_purl_slot_drops_version_and_keeps_npm_scope():
    assert purl_slot("pkg:npm/@next/env@13.0.0") == "pkg:npm/@next/env"
    assert purl_slot("pkg:npm/@next/env") == "pkg:npm/@next/env"
    assert purl_slot("pkg:pypi/django@4.2?arch=x") == "pkg:pypi/django"


def test_second_run_reuses_unchanged_verdicts_and_says_so():
    with WorldModelClient() as world:
        first, _ = _run([_axios()], world, incremental=True)
        assert first.reused == []
        assert [card.verdict for card in first.ranked] == ["affected"]
        second, events = _run([_axios()], world, incremental=True)
    assert second.reused == [AXIOS]
    [card] = second.ranked
    assert card.reused_from == first.run_id
    assert card.verdict == "affected"
    assert any(event["type"] == "reuse" and event["payload"]["case_id"] == AXIOS for event in events)
    assert not any(event["actor"] == "critic" for event in events), "a reused case does not go to the Critic"
    assert f"(reused from {first.run_id})" in to_markdown(second)


def test_changed_range_or_full_run_is_triaged_again():
    with WorldModelClient() as world:
        first, _ = _run([_axios()], world, incremental=True)
        changed, events = _run([_axios(fixed="0.21.2")], world, incremental=True)
        assert changed.reused == []
        assert [card.verdict for card in changed.closed] == ["not_affected"]
        [card] = changed.closed
        assert card.previous_verdict == "affected" and card.previous_run == first.run_id
        assert any(event["actor"] == "critic" for event in events)
        full, _ = _run([_axios(fixed="0.21.2")], world, incremental=False)
        assert full.reused == []


def test_new_epss_rescores_a_reused_case_without_the_critic():
    with WorldModelClient() as world:
        first, _ = _run([_axios()], world, incremental=True)
        hotter = _axios()
        hotter.epss_percentile = 0.95
        hotter.exploited = True
        second, events = _run([hotter], world, incremental=True)
    assert second.reused == [AXIOS]
    assert second.ranked[0].score > first.ranked[0].score
    assert second.ranked[0].exploited is True
    assert not any(event["actor"] == "critic" for event in events)


def test_service_scoped_run_keeps_other_services_current():
    other = _axios()
    other.case_id = other.case_id.replace("internal-admin", "checkout-api")
    for row in other.rows:
        row["service_id"] = "checkout-api"
    with WorldModelClient() as world:
        _run([_axios(), other], world, incremental=True)
        _run([_axios()], world, incremental=True, services=["internal-admin"])
        current = {item["case_id"] for item in world.current_cases()}
    assert current == {AXIOS, other.case_id}
