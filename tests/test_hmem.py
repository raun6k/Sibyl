"""H-MEM round trip: seeded trust, a pending change, and a restart."""

from __future__ import annotations

from pathlib import Path

from sibyl.engines.hmem import HmemClient


def test_hmem_trust_survives_restart(tmp_path: Path):
    store = tmp_path / "hmem"
    with HmemClient(store) as client:
        assert client.trust("osv") == 0.95
        assert client.trust("nvd-cpe", "severity") == 0.7
        resolved = client.resolve(
            {
                "case_id": "case:demo",
                "decision": "affected",
                "note": "checked the advisory",
                "user": "priya",
                "remember": True,
                "scope": "this_case",
            }
        )
        assert resolved["resolution"]["decision"] == "affected"
        assert resolved["pending"] is None
        pending = client.resolve(
            {
                "case_id": "case:other",
                "decision": "affected",
                "note": "trust the CNA text more",
                "user": "priya",
                "remember": True,
                "scope": "adjust_trust",
                "source": "cna",
                "field": "affected_ranges",
                "ecosystem": "*",
            }
        )
        change = pending["pending"]
        assert change["kind"] == "trust"
        assert change["weight"] == 0.9
        assert client.trust("cna") == 0.8
        approved = client.approve(change["id"])
        assert approved["ok"] is True
        assert client.trust("cna") == 0.9
        assert client.resolution_for("case:demo")["decision"] == "affected"
    with HmemClient(store) as again:
        assert again.trust("cna") == 0.9
        assert again.trust("osv") == 0.95
        assert again.resolution_for("case:demo")["case_id"] == "case:demo"
        again.reset()
        assert again.trust("cna") == 0.8


def test_a_human_fact_outranks_a_later_derivation(tmp_path: Path):
    with HmemClient(tmp_path / "hmem") as client:
        first = client.record_fact("svc-web", "internet_facing", False, origin="derived", confidence=0.4)
        assert first["current"]["value"] is False and first["overruled"] is False
        human = client.record_fact("svc-web", "internet_facing", True, origin="human", user="you")
        assert human["current"]["origin"] == "human"
        later = client.record_fact("svc-web", "internet_facing", False, origin="derived", confidence=0.9)
        assert later["overruled"] is True
        assert later["current"]["value"] is True
        assert client.fact_for("svc-web", "internet_facing")["origin"] == "human"
        client.forget_service("svc-web")
        assert client.fact_for("svc-web", "internet_facing") is None
