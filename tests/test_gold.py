"""Gold set shape: 40 labelled pairs, the bucket mix, and every pair in an Acme SBOM."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOLD = ROOT / "eval" / "gold" / "gold.jsonl"
CANDIDATES = ROOT / "eval" / "gold" / "candidates.jsonl"
SBOMS = ROOT / "data" / "sample" / "sboms"

sys.path.insert(0, str(ROOT / "eval" / "gold"))
from select_candidates import QUOTAS  # noqa: E402

FIELDS = {
    "id", "service_id", "purl", "vuln_id", "aliases", "bucket", "label", "hard",
    "fixed_in", "evidence", "note", "labelled_by", "labelled_at", "reviewed_by",
}


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_gold_rows_are_complete():
    rows = _rows(GOLD)
    assert len(rows) == 40
    for row in rows:
        assert set(row) == FIELDS, row["id"]
        assert row["label"] in {"affected", "not_affected"}, row["id"]
        assert isinstance(row["hard"], bool), row["id"]
        assert row["evidence"] and all(url.startswith("https://") for url in row["evidence"]), row["id"]
        assert row["note"].strip(), row["id"]
    assert len({row["id"] for row in rows}) == 40
    assert len({(row["service_id"], row["purl"], row["vuln_id"]) for row in rows}) == 40


def test_gold_bucket_mix_matches_the_plan():
    counts = Counter(row["bucket"] for row in _rows(GOLD))
    assert counts == Counter(QUOTAS)


def test_gold_pairs_are_the_selected_candidates():
    gold = {(r["service_id"], r["purl"], r["vuln_id"], r["bucket"]) for r in _rows(GOLD)}
    picked = {(r["service_id"], r["purl"], r["vuln_id"], r["bucket"]) for r in _rows(CANDIDATES)}
    assert gold == picked


def test_gold_purls_are_in_the_service_sbom():
    for row in _rows(GOLD):
        sbom = json.loads((SBOMS / f"{row['service_id']}.cdx.json").read_text(encoding="utf-8"))
        purls = {component.get("purl") for component in sbom.get("components", [])}
        assert row["purl"] in purls, row["id"]
