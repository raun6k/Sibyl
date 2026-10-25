# Baseline results: full

These are prediction counts over every candidate pair, not scores. Scores against the gold set are in eval/results/eval-full.md.

## B1 NVD-CPE-only

- pairs: 453
- predicted affected: 383
- predicted not affected: 69
- uncertain: 1
- predicted affected per service:
  - checkout-api: 86
  - internal-admin: 103
  - merchant-portal: 68
  - reporting-worker: 126

## B2 OSV-only

- pairs: 639
- predicted affected: 597
- predicted not affected: 42
- uncertain: 0
- predicted affected per service:
  - checkout-api: 156
  - internal-admin: 129
  - merchant-portal: 118
  - reporting-worker: 194

## B3 naive union

- pairs: 674
- predicted affected: 604
- predicted not affected: 70
- uncertain: 0
- predicted affected per service:
  - checkout-api: 156
  - internal-admin: 133
  - merchant-portal: 121
  - reporting-worker: 194
