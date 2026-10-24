"""EPSS URLs are built from the matched CVE list, 100 ids per REST table."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from epss_batches import chunk_cves, expand_creates, table_name, union_body  # noqa: E402

TEMPLATE = (ROOT / "zetaris" / "sql" / "02_rest_tables.sql").read_text(encoding="utf-8")
EPSS_TEMPLATE = TEMPLATE.split("CREATE LIGHTNING REST TABLE epss_batch_000", 1)[1]
EPSS_TEMPLATE = "CREATE LIGHTNING REST TABLE epss_batch_000" + EPSS_TEMPLATE.strip().rstrip(";")


def _cves(count: int) -> list[str]:
    return [f"CVE-2024-{index:05d}" for index in range(count)]


def test_rest_sql_uses_the_placeholder_instead_of_a_hand_written_list():
    assert "{{EPSS_CVES}}" in TEMPLATE
    assert "CVE-2023-4863" not in TEMPLATE
    assert "epss_batch_000" in TEMPLATE


def test_one_batch_when_the_matched_set_is_under_100():
    creates = expand_creates(EPSS_TEMPLATE, _cves(38))
    assert len(creates) == 1
    assert "epss_batch_000" in creates[0]
    assert "epss_batch_001" not in creates[0]
    assert creates[0].count("CVE-2024-") == 38
    assert "UNION ALL" not in union_body(1)
    assert union_body(1).count("LATERAL VIEW explode") == 1


def test_over_100_ids_become_one_table_per_100_and_one_union():
    creates = expand_creates(EPSS_TEMPLATE, _cves(101))
    assert len(creates) == 2
    assert table_name(0) in creates[0]
    assert table_name(1) in creates[1]
    assert creates[0].count("CVE-2024-") == 100
    assert creates[1].count("CVE-2024-") == 1
    body = union_body(2)
    assert body.count("UNION ALL") == 1
    assert body.count("LATERAL VIEW explode") == 2
    batches = chunk_cves(_cves(250))
    assert [len(batch) for batch in batches] == [100, 100, 50]


def test_core_view_joins_v_epss_once_and_does_not_compare_versions():
    text = (ROOT / "zetaris" / "sql" / "05_core_views.sql").read_text(encoding="utf-8")
    body = "\n".join(line for line in text.splitlines() if not line.strip().startswith("--"))
    assert body.count("sibyl_feeds.v_epss") == 1
    assert "version =" not in body.lower()
    assert "VERSIONS" not in body
