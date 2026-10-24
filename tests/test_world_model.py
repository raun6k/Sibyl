"""Python talks to the World Model process and gets a projection back."""

from __future__ import annotations

import json
import subprocess

from sibyl.engines.messages import AliasLink, Claim, CriticDecision
from sibyl.engines.world_model import WorldModelClient, compile_world_model

CASE = "case:internal-admin:pkg:npm/validator@13.7.0:vuln:CVE-2025-56200"


def _claim() -> Claim:
    return Claim(
        case_id=CASE,
        source="osv",
        field="affected_ranges",
        value="fixed 13.15.20",
        raw_ref="osv:GHSA-9965-vmph-33xx",
        retrieved_at="2026-10-24T00:00:00.000Z",
        source_status="active",
    )


def test_python_node_roundtrip_and_empty_diff():
    with WorldModelClient() as world:
        first = world.claim(_claim())
        assert first.changed is True
        assert len(first.ids) == 1
        second = world.claim(_claim())
        assert second.changed is False
        assert second.ids == []
        world.alias_link(
            AliasLink(
                vuln_id="vuln:CVE-2025-56200",
                alias_id="vuln:GHSA-9965-vmph-33xx",
                source="osv",
                confidence=0.95,
            )
        )
        world.critic_decision(
            CriticDecision(case_id=CASE, decision="accept", reason="authoritative range", round=1)
        )
        projected = world.case(CASE)
    assert projected["case_id"] == CASE
    assert len(projected["claims"]) == 1
    assert projected["claims"][0]["raw_ref"] == "osv:GHSA-9965-vmph-33xx"
    assert projected["alias_links"][0]["alias_id"] == "vuln:GHSA-9965-vmph-33xx"
    assert projected["critic_decisions"][0]["decision"] == "accept"
    assert projected["verdict"] is None


def test_concurrent_upserts_keep_audit_order():
    index = compile_world_model().parent / "index.js"
    script = r"""
import { WorldModel } from process.argv[1];
const world = new WorldModel({ storage: "memory", namespace: "fifo" });
const writes = [];
for (let i = 0; i < 20; i++) {
  writes.push(world.upsertEntity({
    type: "x",
    name: "Item " + i,
    source: { kind: "manual", at: "2026-01-01T00:00:00.000Z" },
  }));
}
const results = await Promise.all(writes);
const audit = world.audit();
if (results.length !== 20) throw new Error("lost a write");
if (audit.length !== 20) throw new Error("audit " + audit.length);
for (let i = 1; i < audit.length; i++) {
  if (audit[i].seq <= audit[i - 1].seq) throw new Error("seq went backwards");
}
const ids = new Set(results.map((result) => result.id));
if (ids.size !== 20) throw new Error("ids collided");
console.log(JSON.stringify({ writes: results.length, lastSeq: audit[audit.length - 1].seq }));
"""
    # The import path cannot be a string literal inside the template above.
    program = script.replace("process.argv[1]", json.dumps(index.as_uri()))
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", program],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report == {"writes": 20, "lastSeq": 20}
