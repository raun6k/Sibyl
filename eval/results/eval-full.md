# Eval: full set against the gold set

Gold set: 40 pairs, 26 affected, 18 hard (`eval/gold/gold.jsonl`).
Positive class is `affected`. A pair a system does not report counts as not affected; `uncertain` (every needs-human case, whatever its draft verdict) is not a positive and is wrong for accuracy. Confident means confidence ≥ 0.8.

## Verdicts

| System | Recall | Precision | Accuracy | TP | FP | FN | Uncertain | Wrong-confident |
|---|---|---|---|---|---|---|---|---|
| B1 NVD-CPE-only | 42.3% | 100.0% | 62.5% | 11 | 0 | 15 | 1 | n/a |
| B2 OSV-only | 100.0% | 89.7% | 92.5% | 26 | 3 | 0 | 0 | n/a |
| B3 naive union | 100.0% | 89.7% | 92.5% | 26 | 3 | 0 | 0 | n/a |
| B4 single-pass LLM | 3.9% | 100.0% | 37.5% | 1 | 0 | 25 | 0 | 0.0% of 4 |
| Sibyl | 100.0% | 92.9% | 92.5% | 26 | 2 | 0 | 1 | 5.7% of 35 |
| Sibyl − critic | 100.0% | 92.9% | 92.5% | 26 | 2 | 0 | 1 | 5.7% of 35 |
| Sibyl run 2 | 100.0% | 92.9% | 92.5% | 26 | 2 | 0 | 1 | 5.6% of 36 |

B1 NVD-CPE-only: 17 of 40 predictions were not reported. The table applies the stated missing-as-not-affected scoring rule; this is not a completed model-quality comparison. Token and runtime totals for an incomplete baseline do not support an efficiency ratio.

B2 OSV-only: 4 of 40 predictions were not reported. The table applies the stated missing-as-not-affected scoring rule; this is not a completed model-quality comparison. Token and runtime totals for an incomplete baseline do not support an efficiency ratio.

B3 naive union: 4 of 40 predictions were not reported. The table applies the stated missing-as-not-affected scoring rule; this is not a completed model-quality comparison. Token and runtime totals for an incomplete baseline do not support an efficiency ratio.

B4 single-pass LLM: 36 of 40 predictions were not reported. The table applies the stated missing-as-not-affected scoring rule; this is not a completed model-quality comparison. Token and runtime totals for an incomplete baseline do not support an efficiency ratio.

## Escalation, conflicts, provenance

| System | Escalated gold pairs | Calibrated escalation | Conflict detection | Provenance completeness |
|---|---|---|---|---|
| Sibyl | 1 | 100.0% (1 hard) | 66.7% (6 of 9) | 100.0% (689 of 689 cases) |
| Sibyl − critic | 1 | 100.0% (1 hard) | 44.4% (4 of 9) | 100.0% (689 of 689 cases) |
| Sibyl run 2 | 1 | 100.0% (1 hard) | 66.7% (6 of 9) | 100.0% (689 of 689 cases) |

## Critic effect (Sibyl vs Sibyl − critic)

- Accuracy +0.0 pts, recall +0.0 pts, precision +0.0 pts.
- Send-backs in run 1: 18. Send-backs whose verdict differs without the critic: 0.
- Cases on a different branch (ranked / closed / needs-human): 0.

## Memory effect (run 1 → run 2)

Run 2 is a full-retriage memory ablation: it re-evaluates every case after the human answer. It does not reuse unchanged verdicts, so fresh model judgement can vary on unanswered cases.

Run-1 needs-human gold pairs resolved with their reviewed label: 1.

| | Run 1 | Run 2 |
|---|---|---|
| Escalations | 5 | 5 |
| Needs human | 13 | 14 |
| LLM calls | 91 | 103 |
| Tokens | 248678 | 256631 |
| Wall seconds | 1168.8 | 1372.6 |
| Accuracy on the 39 pairs not resolved | 94.9% | 92.3% |

## Runtime and tokens

| System | Wall seconds | Tokens | LLM calls | Cases | Tokens per case |
|---|---|---|---|---|---|
| B4 single-pass LLM | 107.7 | 38939 | 113 | 40 | 973.5 |
| Sibyl | 1168.8 | 248678 | 91 | 689 | 360.9 |
| Sibyl − critic | 526.2 | 120652 | 43 | 689 | 175.1 |
| Sibyl run 2 | 1372.6 | 256631 | 103 | 689 | 372.5 |

## Per pair

| Id | Pair | Bucket | Label | B1 NVD-CPE-only | B2 OSV-only | B3 naive union | B4 single-pass LLM | Sibyl | Sibyl − critic | Sibyl run 2 |
|---|---|---|---|---|---|---|---|---|---|---|
| G001 | qs@6.5.2 CVE-2026-2391 | straightforward | not_affected | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| G002 | minimatch@5.1.9 CVE-2026-27903 | straightforward | not_affected | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G003 | certifi@2026.10.19 CVE-2024-39689 | straightforward | not_affected | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| G004 | follow-redirects@1.16.1 CVE-2026-40895 | straightforward | not_affected | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| G005 | cryptography@41.0.3 CVE-2023-49083 | straightforward | affected | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| G006 | body-parser@1.18.3 CVE-2026-12590 | straightforward | affected | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G007 | qs@6.7.0 CVE-2022-24999 | straightforward | affected | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G008 | gitpython@3.1.32 CVE-2026-44244 | straightforward | affected | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G009 | certifi@2023.7.22 CVE-2024-39689 | straightforward | affected | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G010 | axios@0.21.4 CVE-2026-25639 | straightforward | affected | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G011 | jsonwebtoken@8.5.1 CVE-2022-23539 | straightforward | affected | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G012 | python-multipart@0.0.6 CVE-2026-53539 | straightforward | affected | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G013 | python-dotenv@1.0.1 CVE-2026-28684 | straightforward | affected | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G014 | tar@6.1.0 CVE-2026-29786 | straightforward | affected | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G015 | ws@8.13.0 CVE-2026-45736 | straightforward | affected | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G016 | idna@3.4 CVE-2026-45409 | nvd_gap | affected | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G017 | node-forge@1.3.1 CVE-2026-33891 | nvd_gap | affected | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G018 | postcss@8.4.31 CVE-2026-41305 | nvd_gap | affected | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G019 | cryptography@41.0.3 GHSA-h4gh-qq45-vh27 | nvd_gap (hard) | affected | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G020 | requests@2.31.0 CVE-2024-35195 | nvd_gap | affected | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G021 | ip@1.1.5 CVE-2024-29415 | nvd_gap (hard) | affected | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G022 | next@13.5.6 CVE-2026-44572 | nvd_gap | affected | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G023 | paramiko@3.3.1 CVE-2026-44405 | nvd_gap (hard) | affected | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G024 | djangorestframework@3.14.0 CVE-2026-73228 | nvd_gap | affected | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G025 | tar@6.1.0 CVE-2026-73566 | nvd_gap | affected | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G026 | django@4.2.3 CVE-2023-46695 | range_conflict (hard) | affected | ? | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G027 | validator@13.7.0 CVE-2025-56200 | range_conflict (hard) | affected | ✗ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G028 | axios@0.27.2 CVE-2023-45857 | range_conflict (hard) | affected | ✗ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G029 | aiohttp@3.8.5 CVE-2026-54280 | range_conflict (hard) | not_affected | ✓ | ✗ | ✗ | — | ✗ | ✗ | ✗ |
| G030 | django@4.2.3 CVE-2026-8404 | range_conflict (hard) | affected | ✗ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G031 | semver@5.7.2 CVE-2022-25883 | range_conflict (hard) | not_affected | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G032 | minimatch@5.1.9 CVE-2026-26996 | range_conflict (hard) | not_affected | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G033 | aiohttp@3.8.5 CVE-2026-54276 | range_conflict (hard) | not_affected | ✓ | ✗ | ✗ | — | ✗ | ✗ | ✗ |
| G034 | requests@2.31.0 CVE-2025-62718 | text_only (hard) | not_affected | — | — | — | — | ✓ | ✓ | ✓ |
| G035 | append-field@1.0.0 CVE-2026-5079 | text_only (hard) | not_affected | — | — | — | — | ✓ | ✓ | ✓ |
| G036 | body-parser@1.19.0 CVE-2026-82417 | text_only (hard) | not_affected | — | — | — | — | ✓ | ✓ | ? |
| G037 | safer-buffer@2.1.2 CVE-2026-82417 | text_only (hard) | not_affected | — | — | — | — | ✓ | ✓ | ✓ |
| G038 | pillow@10.0.1 CVE-2023-4863 | special (hard) | not_affected | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| G039 | braces@3.0.2 CVE-2026-93687 | special (hard) | not_affected | — | ✗ | ✗ | — | ? | ? | ✓ |
| G040 | pillow@9.5.0 CVE-2023-4863 | special (hard) | affected | — | ✓ | ✓ | — | ✓ | ✓ | ✓ |

✓ correct, ✗ wrong, ? uncertain, — not reported (scored as not affected).
