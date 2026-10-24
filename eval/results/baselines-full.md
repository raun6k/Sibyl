# Baseline results: full

These numbers check that the code works. They are not results. There is no gold set yet (P5), and the fixture subset is hand-picked.

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
