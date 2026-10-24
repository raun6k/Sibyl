# Sample data

Acme Payments is a fictional company. Its four services use real public packages at pinned older versions, so real advisories match. The vulnerability files are real API responses. Nothing here is a secret: the committed subset was scanned for `NVD_API_KEY`, `GITHUB_TOKEN`, the contact email, and the other values in `.env`. The hits on the words `Bearer` and `apiKey` are sentences inside advisory text, not credentials.

## Window

`2026-10-09T00:00:00Z` inclusive to `2026-10-23T00:00:00Z` exclusive. A vulnerability counts as in the window when it was modified or published in that range. The window is fixed in `scripts/snapshot_sources.py` so a rerun stays comparable.

## What is on disk

| Tree | In git | Size | What it is |
|---|---|---|---|
| `data/sample/snapshots/` | no | 135 MB | Full download from 2026-10-23 08:29 UTC to 2026-10-24 11:57 UTC |
| `data/sample/snapshot-subset/` | yes | 18 MB (18,187,231 bytes, including its manifest) | Same Acme results, with NVD windows and EUVD bodies trimmed |

Full download, by directory: `euvd/` 92 MB (430 per-CVE files; `CVE-2023-48795.json` is 4 MB), `nvd/` 27 MB (22 MB of that is 17 `window-*` pages, 14 of them gzipped), `ghsa/` 5 MB, `osv/` 4.5 MB, `cve/` 3.9 MB, `kev/` 1.7 MB, `manifest.json` about 1 MB, `epss/` 76 KB.

Subset, by directory: `nvd/` 5.1 MB, `ghsa/` 5.0 MB, `osv/` 4.5 MB, `cve/` 3.9 MB, `kev/` 1.7 MB, `euvd/` 1.7 MB, `manifest.json` 504 KB, `epss/` 76 KB.

The subset manifest (`data/sample/snapshot-subset/manifest.json`) records sha256, size, and what was trimmed for every file.

`.env.example` sets `SNAPSHOT_DIR=data/sample/snapshot-subset`. The code default, when that variable is unset, is still `data/sample/snapshots/` (the full download, present on a machine that has run the fetcher).

## Trim rule

`scripts/trim_snapshots.py` reads the full tree and replaces the subset.

- KEV, EPSS, OSV, GHSA, and CVE.org are copied byte for byte.
- NVD per-CVE files are copied byte for byte.
- NVD window pages keep a vulnerability when a CPE product name matches an Acme package (the same package string baseline B1 joins on) or when that CVE id is already in OSV, GHSA, or CVE.org. Other window entries cannot reach an Acme component. Gzipped pages are stored uncompressed after the trim. Top-level page fields other than `vulnerabilities` stay as they were.
- EUVD files keep only the fields the collector reads: `id`, `aliases`, `baseScore`, `baseScoreVector`, `baseScoreVersion`, and `error` / `message` on a not-found body. `enisaIdAdvisory` and `references` are what made those files large.

Checked on 2026-10-24. Reset `evidence`, ingest the full tree, then reset and ingest the subset. These matched exactly:

- `v_candidate_matches` rows: checkout-api 24571, internal-admin 824, merchant-portal 852, reporting-worker 46593
- matcher combined drafts: 600 affected, 62 not affected, 12 uncertain, 674 cases; 11 blocking conflicts and 3 informational
- baselines: B1 453 pairs (383 predicted affected), B2 639 pairs (597 predicted affected)
- text-only cases opened from CVE.org and NVD prose: 15

NVD source records fall from 33042 to 445. That is the dropped window entries. Aliases stay 6166. EPSS for the matched set is 443 CVE ids, which does not fit one FIRST URL (the limit is 100), so it is five REST tables, `epss_batch_000` through `epss_batch_004`, unioned once in `v_epss`.

Two EUVD files are HTTP 404 bodies for CVE-2026-112899 and CVE-2026-112902 (`EUVD not found`). CVE.org has the matching 404 bodies. Those ids are not records. No other parse failure.

## Sources and licences

Responses are stored as returned, except for the trim above.

| Source | What is stored | Terms |
|---|---|---|
| OSV | Query-batch responses for the Acme purls, then one document per matched id | [OSV](https://osv.dev) aggregates upstream databases. Those upstream terms still apply. The API responses are used as returned. |
| GitHub Advisory Database | Reviewed pip and npm advisories modified in the window, plus each GHSA id OSV returned | [CC-BY 4.0](https://github.com/github/advisory-database) |
| CISA KEV | The full catalogue | US government work, public domain |
| FIRST EPSS | One batch file per 100 CVE ids from the OSV and in-window GHSA sets. The NVD window is fetched later, so its CVE ids are not in these files | [FIRST EPSS](https://www.first.org/epss/) public scores. FIRST's data policy asks for attribution |
| NVD 2.0 | CVEs modified in the window, paged at 2,000, plus a per-CVE file for each matched id that the window did not already contain | [NVD](https://nvd.nist.gov) public data, published by NIST |
| CVE.org | `GET /api/cve/{id}` for each matched CVE id | [CVE Program](https://www.cve.org) records. CVE is a trademark of The MITRE Corporation. The records are free to use under the CVE terms |
| ENISA EUVD | The exploited-vulnerability list, plus one lookup per matched CVE id | [EUVD](https://euvd.enisa.europa.eu) public service. Per-id files in the subset keep only the collector fields |

## Regenerate

Full download, from the repo root. Without `NVD_API_KEY` and `GITHUB_TOKEN` the run that finished on 2026-10-24 took about 27.5 hours: NVD waits 6 seconds between calls, and GitHub is capped at 58 requests an hour with 61 seconds between them. `NVD_API_KEY` shortens the NVD gap to 0.6 seconds. `GITHUB_TOKEN` shortens GitHub to 0.8 seconds and removes the hourly cap. Files that already exist are skipped unless `--force` is passed. The full tree is gitignored.

```bash
uv run scripts/snapshot_sources.py
uv run scripts/snapshot_sources.py --since 2026-10-09T00:00:00Z --until 2026-10-23T00:00:00Z
```

Then rebuild the committed subset:

```bash
uv run scripts/trim_snapshots.py
```

That reads `data/sample/snapshots/` and replaces `data/sample/snapshot-subset/`.

Offline tests do not read either tree. They use `tests/fixtures/snapshots/`, regenerated with `uv run scripts/freeze_fixtures.py`.

## Acme SBOMs

Lockfiles live in `data/sample/internal/lockfiles/`. `scripts/gen_sboms.sh` runs `@cyclonedx/cdxgen` 12.9.0 with `FETCH_LICENSE=false` and writes `data/sample/sboms/<service>.cdx.json` (CycloneDX 1.6). Four services, 422 components. `uv run scripts/seed_db.py` loads them into Postgres. `uv run scripts/seed_db.py --reset-evidence` truncates `evidence` records first and leaves `runs` and `run_events` in place. Ingest upserts and does not delete rows that are absent from the new batch, so reset before switching between the full download, the subset, and the fixtures.
