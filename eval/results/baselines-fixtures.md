# Baseline results: fixtures

These numbers check that the code works. They are not results. There is no gold set yet (P5), and the fixture subset is hand-picked.

## B1 NVD-CPE-only

- pairs: 24
- predicted affected: 21
- predicted not affected: 3
- uncertain: 0
- predicted affected per service:
  - checkout-api: 3
  - internal-admin: 10
  - merchant-portal: 7
  - reporting-worker: 1

## B2 OSV-only

- pairs: 63
- predicted affected: 57
- predicted not affected: 6
- uncertain: 0
- predicted affected per service:
  - checkout-api: 13
  - internal-admin: 17
  - merchant-portal: 15
  - reporting-worker: 12
