# Gold set

40 (component@version, vulnerability) pairs from the sample SBOMs, each labelled `affected` or `not_affected` from upstream evidence: the fix commit and the first tag that contains it, release notes, or the code at the installed tag. A label never comes from Sibyl's output or from a single feed.

| File | What it is |
|---|---|
| `select_candidates.py` | Picks the pairs from `output_examples/full/report.json` and `eval/results/baselines-full.jsonl`, using only what the sources said |
| `candidates.jsonl` | The 40 picks, unlabelled, with each source's position and the B1 prediction |
| `gold.jsonl` | The labelled set |

`tests/test_gold.py` checks the row shape, the bucket mix, that the pairs are the picks, and that every purl is in its service's SBOM.

## Buckets

| Bucket | Count | Rule |
|---|---|---|
| straightforward | 15 (4 not affected) | GHSA, OSV and NVD present and agree |
| nvd_gap | 10 | No NVD position and no B1 row |
| range_conflict | 8 | Sources or B1 disagree, or NVD says affected and OSV does not list it |
| text_only | 4 | No structured range; opened from CVE.org or NVD prose |
| special | 3 | A withdrawn record or a KEV-listed CVE |

`hard: true` marks conflict, text-only, withdrawn and KEV pairs, plus any pair whose label needed reading code or has no fixed release. The calibrated-escalation metric uses it.

## Labelling rules

- **Affected:** the installed tag lacks the fix commit (checked with the GitHub compare API) and the vulnerable code is present at that tag.
- **Backport branches:** the main-branch fix commit is not on the 5.x or 6.x lines, so these use the branch's own backport commit or the changelog.
- **Text-only:** a CVE assigned to another package (axios prose matching `requests`, qs prose matching `body-parser`) is `not_affected` for the matched component. append-field is `not_affected` because the fix lives in multer.
- **Withdrawn:** a GHSA withdrawal decides the label even while the CNA record is live (braces).
- **Wheels:** PyPI installs are assumed to be wheels, which matters for Pillow (bundled libwebp) and cryptography (bundled OpenSSL).
- **Excluded:** a case upstream cannot settle, or one whose label would contradict every source, is listed in `EXCLUDED` with its reason, and the next case in its bucket takes its place. Every label in the set agrees with at least one source or with B1. Three cases are excluded:
  - **pyjwt CVE-2025-45768:** the supplier disputes it and the GHSA is unreviewed.
  - **axios@0.21.4 CVE-2026-101902:** every source starts at 0.27.2, but the 0.21.4 merge code reads an inherited `method` the same way.
  - **django@4.2.3 CVE-2026-53877:** the 4.2 series is unevaluated, but 4.2.3 has the line the fix changes.

## Regenerate the picks

```bash
python3 eval/gold/select_candidates.py
```

The pick is deterministic: within a bucket it orders cases by sha256 of the case id and takes them round robin across services.
