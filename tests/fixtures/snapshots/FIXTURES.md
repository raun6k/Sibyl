# Frozen fixtures

These files are real API responses (or, for `*.request.json` only, the POST body rebuilt from the SBOM purls). Part E re-runs ingestion, the Zetaris check, the matcher, and the baselines on the full snapshots. This directory stays the offline test set and is not replaced by those snapshots.

Regenerate the copied subset with `uv run scripts/freeze_fixtures.py`. That reads `data/sample/snapshots/` and rewrites `osv/`, `ghsa/`, `kev/`, `epss/`, and `nvd/`. `uv run scripts/freeze_fixtures.py --fetch-missing` also does at most 12 GETs (`User-Agent: sibyl (<CONTACT_EMAIL>)`) for CVE.org and EUVD, and skips that work only when you leave the existing `cve/` and `euvd/` files in place. Delete those two directories first if you want them fetched again. The contact email is not written into these files.

Fetch dates on snapshot copies are the local file modification time in UTC, which is when the snapshot script wrote the file. The snapshot manifest does not store a fetch timestamp for these objects.

Synthetic 429 and 5xx responses are not files. Tests build them with `httpx.MockTransport`. A malformed body and an empty body live in `tests/fixtures/synthetic/` and are marked synthetic in the file itself. The prompt-injection advisory is P5 and is not here.

## Selection

- Selected 40 OSV vulnerability documents from 655 on disk.
- Withdrawn OSV records on disk: 0. None were present, so none are in the fixture. That count is OSV only. The withdrawn GHSA record on the pip list page is GHSA-p3hm-x653-5rc6 (ip-address). It matches no sample component. Four other withdrawn GHSA records are on disk now (nodemailer, sprintf-js, openclaw, lmcache); none of those packages are in the sample SBOMs.
- OSV records whose CVE alias is in the KEV catalogue: 2 on disk, 2 selected. The target was 3. Only the records that exist were copied.
- PYSEC ids: 6 selected (target 5, 214 on disk).
- Records with a GHSA per-advisory file: 8 selected (target 5, 8 on disk).
- Records with an NVD per-CVE file: 35 selected (target 5, 300 on disk).
- Records where the OSV and GHSA ranges differ: 14 selected (target 3, 38 on disk).
- Services: checkout-api=15, merchant-portal=14, reporting-worker=15, internal-admin=15.
- Ecosystems: pypi=20, npm=21.
- EPSS: one fixture CVE, CVE-2023-5129, is not in any EPSS batch on disk. It is an alias on the libwebp records (GHSA-j7hp-h8jx-5ppr and PYSEC-2026-1794) beside CVE-2023-4863, which is in batch-000.
- Ids: GHSA-22hg-r758-rrw9, GHSA-2328-f5f3-gj25, GHSA-239g-whfq-7xj9, GHSA-23c5-xmqv-rm74, GHSA-23hp-3jrh-7fpw, GHSA-23wx-cgxq-vpwx, GHSA-248v-346w-9cwc, GHSA-254f-3936-288h, GHSA-27h8-gf7j-v5hc, GHSA-29mw-wpgm-hmr9, GHSA-2m57-hf25-phgg, GHSA-2mcm-79hx-8fxw, GHSA-2p57-rm9w-gvfp, GHSA-33f9-j839-rf8h, GHSA-35jh-r3h4-6jhm, GHSA-37ch-88jc-xwx2, GHSA-3h52-269p-cp9r, GHSA-3h5v-q93c-6h6q, GHSA-3jfq-g458-7qm9, GHSA-3p68-rc4w-qgx5, GHSA-3rfm-jhwj-7488, GHSA-4342-x723-ch2f, GHSA-4558-3h8r-v8xp, GHSA-58r4-6rv3-gfh8, GHSA-6rw7-vpxm-498p, GHSA-7gfc-8cq8-jh5f, GHSA-7m27-7ghc-44w9, GHSA-7mwm-ghpf-9vrm, GHSA-8cf7-32gw-wr33, GHSA-8g5g-8vmr-9782, GHSA-952p-6rrq-rcjv, GHSA-9hjg-9r4m-mvj7, GHSA-j7hp-h8jx-5ppr, GHSA-pchr-8j38-3x4p, PYSEC-2021-142, PYSEC-2023-161, PYSEC-2024-230, PYSEC-2026-1794, PYSEC-2026-1872, PYSEC-2026-3982.

## CVE.org and EUVD

- EUVD exploited list paging: the call `fetch_euvd` makes, `GET /api/exploitedvulnerabilities` with no query string, does not page. ENISA documents it as the latest exploited vulnerabilities, maximum 8 records. This response is HTTP 200, a JSON array of 4 objects, and it has no page, total, or Link header. A follow-up `GET` with `?page=0&size=5` returned the same four ids, so those parameters are ignored. The searchable catalogue is a different endpoint, `/api/search`, which does page (`page` starting at 0, `size` max 100, including `exploited=true`). Item fields: id, enisaUuid, description, datePublished, dateUpdated, baseScore, baseScoreVersion, baseScoreVector, references, aliases, assigner, epss, exploitedSince, enisaIdVendor. `aliases` is one newline-separated string, not an array.
- GET calls used: 11 of 12.
- CVE.org ids saved: CVE-2023-4863, CVE-2020-28500, CVE-2021-23337, CVE-2022-23539, CVE-2022-37603.
- At least one saved CVE.org id is in the KEV catalogue.


## Shapes added from the snapshot check

`scripts/check_snapshots.py` read `data/sample/snapshots/` and wrote nothing to Postgres. These files are the real responses that showed a field or value the first freeze did not contain. `nvd/window-001.json` is the only trimmed one.

- OSV CVSS 3.0 vector: `osv/vuln-GHSA-c36v-fmgq-m8hx.json` (immer).
- GHSA advisory CVSS 3.0 vector (`cvss_severities.cvss_v3`): `ghsa/advisory-GHSA-c36v-fmgq-m8hx.json`. The collector reads the version from the vector, so this stays 3.0 and is not labelled 3.1.
- NVD `cpeMatch.versionStartExcluding`: `nvd/window-001.json` (CVE-2022-0778, CVE-2022-1184).
- CVE.org `affected[]` keys `collectionURL`, `packageName`, `defaultStatus`: `cve/CVE-2023-0842.json`. The package name in that record is `node-xml2js`. The version `0.4.23` is that one version.
- CVE.org `affected[]` key `cpes`: `cve/CVE-2023-50782.json`. No PyPI or npm package is identified, so there is no affected row.
- CVE.org `affected[]` keys `modules` and `repo`, version text `< 6.14.1`, CVSS 4.0: `cve/CVE-2025-15284.json` (qs).
- CVE.org `affected[]` key `packageURL` with a semver bound: `cve/CVE-2026-77078.json` (multer).
- CVE.org `packageURL` whose `lessThan` is a git commit: `cve/CVE-2026-44405.json` (paramiko). No affected row.
- CVE.org `affected[]` key `platforms`: `cve/CVE-2026-45822.json`.
- CVE.org `programFiles` and `programRoutines`: `cve/CVE-2024-4067.json` (micromatch).
- CVE.org `versions[]` object with `changes` and `lessThanOrEqual`: `cve/CVE-2024-4068.json` (braces).
- CVE.org CVSS 3.0 and `lessThanOrEqual` with version `unspecified`: `cve/CVE-2021-3757.json`.
- CVE.org CVSS 4.0 beside CVSS 3.1: `cve/CVE-2024-21520.json`.

EUVD `CVE-2026-112899.json` and `CVE-2026-112902.json` on disk are `{"error":"EUVD not found"}`. They are not fixtures.

## Critic cases

Searched `data/sample/snapshots/` read-only on 2026-10-24, at the versions the sample SBOMs install. Files modified in the last two minutes were not read. Nothing here was invented. `freeze_fixtures.py --add` copied the per-id files and left every existing fixture file as it was. No live GET was used: the CVE.org and NVD bodies were already on disk.

- **(a) OSV and GHSA disagree at an installed version: none on disk.** Where both sources have a range for the same package and share an id, they agreed (182 pairs affected on both sides, 9 not affected on both sides, counting one installed version per package).
- **(b) No structured range for the package, and the text names it.** internal-admin `append-field@1.0.0`. OSV and GHSA have no affected row for `append-field`. `CVE-2026-77078` (multer, fixed in 2.3.0) says the denial of service throws inside the append-field dependency and is not caught by multer. That sentence is in `cve/CVE-2026-77078.json` and `nvd/cve-CVE-2026-77078.json`. The OSV record for the same CVE, `GHSA-wc9g-mqfw-jrwm`, is a multer range and does not name append-field.
- **(c) Withdrawn or rejected record covering a sample package: none on disk.** See the withdrawn note above. No rejected NVD CPE product name equals a sample package.
- **(d) KEV or EUVD exploited, matched to a sample package.** Only `CVE-2023-4863`. It is already in the fixtures: KEV, pillow `9.5.0` on reporting-worker (affected) and pillow `10.0.1` on checkout-api (the fix). The EUVD exploited list on disk is `CVE-2026-96652`, `CVE-2026-96654`, `CVE-2026-96655`, and `CVE-2026-96656`. None of those join a sample package. There is no second or third matched exploited CVE on disk.
- **(e) NVD CPE and OSV disagree, and the NVD row joins because `target_sw` is node.js.**
  - internal-admin `validator@13.7.0`, `CVE-2025-56200`, OSV `GHSA-9965-vmph-33xx`. OSV is introduced `0`, fixed `13.15.20`, so 13.7.0 is affected. The NVD description says through 13.15.15, and the CPE `versionEndIncluding` is `3.15.15`, so 13.7.0 is outside that bound. Informational: OSV decides the combined draft.
  - internal-admin `axios@0.21.4` and merchant-portal `axios@0.27.2`, `CVE-2023-45857`, OSV `GHSA-wf5p-g6vw-rhxx`. OSV includes `0.8.1` up to `0.28.0`. NVD lists the single version `1.5.1`. Informational.

## Files (131, 6651825 bytes)

| File | Origin | Fetched | SHA256 | Trim |
|---|---|---|---|---|
| `cve/CVE-2020-28500.json` | --fetch-missing | 2026-10-23T10:01:22Z | `9f7b4a00d55a7f2883f9b58bf7b76860f13ca5f06b0d43482994ae481cfa111e` | none. Contains a CISA-ADP container. |
| `cve/CVE-2021-23337.json` | --fetch-missing | 2026-10-23T10:01:22Z | `26901438e5dae4d046baf75c2508a1f44b1e617f680d2e844cf917c8c0fab8ff` | none. Contains a CISA-ADP container. |
| `cve/CVE-2021-3757.json` | snapshot copy | 2026-10-23T11:37:10Z | `18487629ef81a93573adbeb6945751b53164802ccae341cc72a0881aee0bdb12` | none. Added because the CNA metric is CVSS 3.0 and versions[] uses lessThanOrEqual with version unspecified. |
| `cve/CVE-2022-23539.json` | --fetch-missing | 2026-10-23T10:01:22Z | `442763ce9b0e7b9aa07e44f93da770032c89b67d205b5c9b85f7ba848967c0b7` | none. Contains a CISA-ADP container. |
| `cve/CVE-2022-37603.json` | --fetch-missing | 2026-10-23T10:01:22Z | `82d8c72625d7e0ed5e499585abaec52205c2a9cc38024e9701b6a97a8e958fce` | none. Contains a CISA-ADP container. |
| `cve/CVE-2023-0842.json` | snapshot copy | 2026-10-23T11:37:18Z | `c0302ebf837af788c94acc09a33270a35fdaf214eac1fb46b7f22b6c4bdce6ad` | none. Added because affected[] has collectionURL, packageName, and defaultStatus, and one exact npm version. |
| `cve/CVE-2023-45857.json` | snapshot copy | 2026-10-23T11:37:21Z | `accb309f191dfee285f235134640e3b48a5c298d535f83578b5e4fc6cfb41c28` | none. Copied by --add. Files already in the fixture were left unchanged. |
| `cve/CVE-2023-4863.json` | --fetch-missing | 2026-10-23T10:01:22Z | `ebad3c8097c8b086599204b46e3cef87e9a3ba0fd2cc2e8864a1ca80799ac61a` | none. Contains a CISA-ADP container. |
| `cve/CVE-2023-50782.json` | snapshot copy | 2026-10-23T11:37:25Z | `dc2b3fa9dae5f531f54e8cc4e8fb0c450fca17701482b4cc34fee73724e1165e` | none. Added because affected[] carries a cpes array. The package is not identified as PyPI or npm, so it stays severity-only. |
| `cve/CVE-2024-21520.json` | snapshot copy | 2026-10-23T11:37:26Z | `057924abd861491065faa1aafe08108536caf25488c710ed5ae3db348c38f798` | none. Added because the CNA container has a CVSS 4.0 metric beside CVSS 3.1. |
| `cve/CVE-2024-4067.json` | snapshot copy | 2026-10-23T11:37:35Z | `2c529795269ef4095a055c36ab6843d45ed04d929ee862e8243c590ce205b99e` | none. Added because affected[] has programFiles and programRoutines, and versions[] is status, version, versionType. |
| `cve/CVE-2024-4068.json` | snapshot copy | 2026-10-23T11:37:36Z | `3aa6e551dc410f22f55faa4fee6ce6beaf3e8a552829f09af5858a9aae5f9553` | none. Added because versions[] has a changes array and lessThanOrEqual. |
| `cve/CVE-2025-15284.json` | snapshot copy | 2026-10-23T11:37:47Z | `eea687c96d562a00e20a3fd7013e1b47e4a530c331ab5db652298a4bf9460b43` | none. Added because affected[] has modules and repo, the version text is `< 6.14.1`, and the CNA metric includes CVSS 4.0. |
| `cve/CVE-2025-56200.json` | snapshot copy | 2026-10-23T11:37:52Z | `d69dd27064330e349561473de3cb6c32b8df5ad77d56e1694cd590b5abd8a8a3` | none. Copied by --add. Files already in the fixture were left unchanged. |
| `cve/CVE-2026-44405.json` | snapshot copy | 2026-10-23T11:38:40Z | `6d1fad6c2b2bc07d34c5ceb07880db4aba2cb3464dbd2a96f6cadf1a90e7ff20` | none. Added because affected[] uses packageURL. The lessThan bound is a git commit, so no affected row is stored. |
| `cve/CVE-2026-45822.json` | snapshot copy | 2026-10-23T11:38:46Z | `221deb7a91dcc7427923ab79a4e48004c240517f6e052e583ac25de48935f462` | none. Added because affected[] has platforms and no package collection URL. |
| `cve/CVE-2026-77078.json` | snapshot copy | 2026-10-23T11:39:13Z | `babbf68814328ae923758683b5243805be2a3655f0e0c648d7ca423b11a94dd3` | none. Added because packageURL is pkg:npm/multer with a semver lessThan bound. |
| `epss/batch-000.json` | snapshot copy | 2026-10-23T09:14:05Z | `dcf743bdaa2052699feaaf980be36ccbf9ce5b68d7590170d61b405d5cfe2962` | none. Whole batch file. Covers fixture CVEs: CVE-2020-14343, CVE-2020-28500, CVE-2021-23337, CVE-2021-23436, CVE-2021-32804, CVE-2022-23539, CVE-2022-25645, CVE-2022-37603, CVE-2023-40590, CVE-2023-4863, CVE-2024-29415, CVE-2024-37890, CVE-2024-39689, CVE-2024-4067. |
| `epss/batch-001.json` | snapshot copy | 2026-10-23T09:14:05Z | `4278db3859a4161f1cfb4ae8b59e9291900f798e8cf25ab95f4b94c213913244` | none. Whole batch file. Covers fixture CVEs: CVE-2024-4340, CVE-2024-45296, CVE-2024-47081, CVE-2024-51479, CVE-2024-56332, CVE-2025-13473, CVE-2025-15284, CVE-2025-48068, CVE-2025-57822, CVE-2025-62718. |
| `epss/batch-002.json` | snapshot copy | 2026-10-23T09:14:06Z | `d32184e3df60ea904b4be9a5b904c52cfbc04f1cf0cc0c17d125ebd99a336c67` | none. Whole batch file. Covers fixture CVEs: CVE-2026-112390, CVE-2026-112391, CVE-2026-112392, CVE-2026-112394, CVE-2026-112397, CVE-2026-112402, CVE-2026-112403, CVE-2026-112896. |
| `epss/batch-003.json` | snapshot copy | 2026-10-23T09:14:06Z | `a1fe53771d31590b8f99c2df6f00ac7914659bcb90f0fb4557cb636879110b0d` | none. Whole batch file. Covers fixture CVEs: CVE-2026-27904. |
| `epss/batch-004.json` | snapshot copy | 2026-10-23T09:14:07Z | `62554f49c85a49663361d3dd43481c2000dd145ce7c7176040cb95ab16eacfd9` | none. Whole batch file. Covers fixture CVEs: CVE-2026-33896, CVE-2026-4867. |
| `epss/batch-005.json` | snapshot copy | 2026-10-23T09:14:08Z | `9040e24cc995afdc549b52e7395d547f812490bf254cd7452c391fc3a9805b0b` | none. Whole batch file. Covers fixture CVEs: CVE-2026-59873, CVE-2026-87817. |
| `euvd/CVE-2020-28500.json` | --fetch-missing | 2026-10-23T10:01:25Z | `ff89bc499a15ee586e168c11191b112be25940fc7065f5e8604f2851ceb3d03f` | none. HTTP 200. This is the fetch_euvd per-id call. |
| `euvd/CVE-2021-23337.json` | --fetch-missing | 2026-10-23T10:01:26Z | `3fa9ebb54324df1c728431eff1c2d7cede513550d91de7bdce3be0c1cce90446` | none. HTTP 200. This is the fetch_euvd per-id call. |
| `euvd/CVE-2022-23539.json` | --fetch-missing | 2026-10-23T10:01:27Z | `5a741fa90188017028a45185981812d896a1b42f151a6fbaa294f553574c45f5` | none. HTTP 200. This is the fetch_euvd per-id call. |
| `euvd/CVE-2022-37603.json` | --fetch-missing | 2026-10-23T10:01:27Z | `2b71975c309ed4bc1a5fda8d19d956ae50c12c772a692b81509e264b9777704e` | none. HTTP 200. This is the fetch_euvd per-id call. |
| `euvd/CVE-2023-45857.json` | snapshot copy | 2026-10-23T11:39:48Z | `3f2bb47bcea100e55cc10f6fdef7a90a7c9b649cb8971ef0860b94335aeeec2b` | none. Copied by --add. Files already in the fixture were left unchanged. |
| `euvd/CVE-2023-4863.json` | --fetch-missing | 2026-10-23T10:01:24Z | `f7b8f5822c92f4ee925b4b531d0e682709fce659bbe52bf279b12edd69f5cc4a` | none. HTTP 200. This is the fetch_euvd per-id call. |
| `euvd/CVE-2025-56200.json` | snapshot copy | 2026-10-23T11:40:54Z | `3c3fce784560502ad57fb638cf2bf61485cd36b43c18fc7f1efa6f9872659356` | none. Copied by --add. Files already in the fixture were left unchanged. |
| `euvd/exploitedvulnerabilities.json` | --fetch-missing | 2026-10-23T10:01:05Z | `5f44cad45acdb1152dce5e8b2a1adb4c23ca10d9015d2022a328488ceed0f6b6` | none. HTTP 200 final url: https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities json list length 4 json item keys: id, enisaUuid, description, datePublished, dateUpdated, baseScore, baseScoreVersion, baseScoreVector, references, aliases, assigner, epss, exploitedSince, enisaIdVendor |
| `ghsa/advisories-npm-000.json` | snapshot copy | 2026-10-23T08:35:56Z | `167df33f105373f414ecc222bb9d355bcc40b6f6d6fde6eb931b0f14153035b4` | none. First list page for this ecosystem. Later pages were not copied. |
| `ghsa/advisories-pip-000.json` | snapshot copy | 2026-10-23T08:33:54Z | `618029045b65c889de878652dd47f06f22a8b9a39f49ecd4422f2c0631c9949b` | none. First list page for this ecosystem. Later pages were not copied. |
| `ghsa/advisory-GHSA-2328-f5f3-gj25.json` | snapshot copy | 2026-10-23T08:37:57Z | `22fcc41d07e0722ccb46a9c06d0da1d65983870053abf0a0555bdfef8ce934cd` | none |
| `ghsa/advisory-GHSA-239g-whfq-7xj9.json` | snapshot copy | 2026-10-23T08:38:58Z | `30253b5e1b94a10b47f9dfa6b5e776ca58d018197182940d04c7dad6645f5672` | none |
| `ghsa/advisory-GHSA-23c5-xmqv-rm74.json` | snapshot copy | 2026-10-23T08:39:59Z | `05e61511cbb479c88692d19ba5a6b047af0cf33eefd9c9e125615b4ed26012c1` | none |
| `ghsa/advisory-GHSA-23hp-3jrh-7fpw.json` | snapshot copy | 2026-10-23T08:41:00Z | `b37d326e8e02d1dfd5286b3f65386e6fe89410df884b39c22346873862196b90` | none |
| `ghsa/advisory-GHSA-23wx-cgxq-vpwx.json` | snapshot copy | 2026-10-23T08:42:01Z | `91d1e1fad3c6e84469575723fbc856a3001d45de7f6fd6ece74556c637e95c96` | none |
| `ghsa/advisory-GHSA-248v-346w-9cwc.json` | snapshot copy | 2026-10-23T08:43:02Z | `56aadee83ce66f4fc541ac12c85c37142c2626a495d7f0c27bfd4d9b242f69a5` | none |
| `ghsa/advisory-GHSA-c36v-fmgq-m8hx.json` | snapshot copy | 2026-10-24T06:57:01Z | `19b7a0cce3282ee479167c1fe092577c7436f7ececd21daa9f22e1ac255a4035` | none. GHSA `cvss_v3` vector is CVSS:3.0. Added so the GHSA collector, not only the OSV record, covers that version. |
| `kev/known_exploited_vulnerabilities.json` | snapshot copy | 2026-10-23T09:14:04Z | `ef8fffede5c472001da046c7751beb2a3242458896d0ce08da52b30968b8b56b` | none. Full catalogue. |
| `nvd/cve-CVE-2020-14343.json` | snapshot copy | 2026-10-23T09:37:50Z | `255aac1b34caf336b993bb09510e4326b4af0b339114928e29bf0b061ff778bc` | none |
| `nvd/cve-CVE-2020-28500.json` | snapshot copy | 2026-10-23T09:38:03Z | `14e40b0dff17e276481e3b4db23a3079031c073b49605d22d6ffe75645bde1a8` | none |
| `nvd/cve-CVE-2021-23337.json` | snapshot copy | 2026-10-23T09:38:15Z | `262d325630d6a90b831c35ae0f6d1dd1f545071b8e738ad31a0b0dea3a2e19ce` | none |
| `nvd/cve-CVE-2021-23436.json` | snapshot copy | 2026-10-23T09:38:27Z | `d769c18da680a78d09f326486a89d86b00057142e46de3a4e3f7072b36d1b375` | none |
| `nvd/cve-CVE-2021-32804.json` | snapshot copy | 2026-10-23T09:38:39Z | `0df05a04ba5b66c84c14d62a07fde9f2f9ab1479424ae800345587a4fd98394e` | none |
| `nvd/cve-CVE-2022-23539.json` | snapshot copy | 2026-10-23T09:39:38Z | `623dbbfb7d9211164be5f41d0d78b2015085d3314b02aa3646c7008af65b58c6` | none |
| `nvd/cve-CVE-2022-25645.json` | snapshot copy | 2026-10-23T09:40:20Z | `9e2bb3ab4585ff9070c1750adde48d1e3841123efd5affcf70b7e451b71deabc` | none |
| `nvd/cve-CVE-2022-37603.json` | snapshot copy | 2026-10-23T09:41:02Z | `b32388c237ba211289d657a10abbdc64bfd63d072b4d839654a9dda83f29dc68` | none |
| `nvd/cve-CVE-2023-40590.json` | snapshot copy | 2026-10-23T09:41:39Z | `9e45b6d13379ffdbd90d078147786e296a7ed4e902494cddcd1bd76ab02d949f` | none |
| `nvd/cve-CVE-2023-45857.json` | snapshot copy | 2026-10-23T09:42:27Z | `56e73a61d937bcb1161927332728eef505cab3ad841acaa1e478b1c7c9108020` | none. Copied by --add. Files already in the fixture were left unchanged. |
| `nvd/cve-CVE-2023-4863.json` | snapshot copy | 2026-10-23T09:42:51Z | `088c345d717064a5c773a1e617910065b87a08021c78dcaa1dd765126ab391f8` | none |
| `nvd/cve-CVE-2023-5129.json` | snapshot copy | 2026-10-23T09:43:33Z | `e7fe4302a3c44078704b34456196a8b18dc7f1f03610c89552d1c9960c02cb58` | none |
| `nvd/cve-CVE-2024-29415.json` | snapshot copy | 2026-10-23T09:45:20Z | `c482cb286da6170d450643f7a3dce7dbcb8dc3a245b912faceb35df55717b4c5` | none |
| `nvd/cve-CVE-2024-37890.json` | snapshot copy | 2026-10-23T09:48:08Z | `4fe1e2f92b85ff5748f46c35a8172ae71d99cf5b6f6faf10d6765bd42fda60f1` | none |
| `nvd/cve-CVE-2024-39689.json` | snapshot copy | 2026-10-23T09:48:44Z | `f980fb3d252bec326e9d6f4ef0a1bedc4a36aeea6a597108d6a5be6cb05515c2` | none |
| `nvd/cve-CVE-2024-4067.json` | snapshot copy | 2026-10-23T09:48:50Z | `2077b43d271df2df928962280caaf20de2f91030f96ad28d464e125363790ac3` | none |
| `nvd/cve-CVE-2024-4340.json` | snapshot copy | 2026-10-23T09:49:28Z | `27a5002cf9e80ecc1e648624135774b998286676b62a043875dca9e9f6ad69c3` | none |
| `nvd/cve-CVE-2024-45296.json` | snapshot copy | 2026-10-23T09:50:02Z | `5a8767d2cefff3b35e4c7bf7b6ec61580bb42ed3151d4d415a612c94f8bc2f17` | none |
| `nvd/cve-CVE-2024-47081.json` | snapshot copy | 2026-10-23T09:50:20Z | `8362e75237e89bcfb20df2f5cebc4bd67217541ab8f81ac7e4097aeceb01f6bb` | none |
| `nvd/cve-CVE-2024-51479.json` | snapshot copy | 2026-10-23T09:50:50Z | `749f63596aa73f96eb9a04f9e60661883c20b66fbb9b602d854672160924c330` | none |
| `nvd/cve-CVE-2024-56332.json` | snapshot copy | 2026-10-23T09:51:44Z | `62c93f4816d7ff7b89829fc3877e7bb23392ec6edd68c1f4133c151df2479bff` | none |
| `nvd/cve-CVE-2025-13473.json` | snapshot copy | 2026-10-23T09:53:08Z | `29181027fc8ae14737083706db9f3369cd1488b0073c86d4c3f6c79005a2acc9` | none |
| `nvd/cve-CVE-2025-15284.json` | snapshot copy | 2026-10-23T09:53:20Z | `a03fc3fb8389fa82f7a4b99b9b61c7c160cddb8c6a2fc3b12ac510736a5152eb` | none |
| `nvd/cve-CVE-2025-48068.json` | snapshot copy | 2026-10-23T09:54:15Z | `f77cc472f3719956222dd0b7af4af98390470d0272dc62116481bf4b0eed1371` | none |
| `nvd/cve-CVE-2025-56200.json` | snapshot copy | 2026-10-23T09:54:45Z | `dc3e399af06ea0865955a5b170234bfd03b94acabe18507890e6d40cf372b6b8` | none. Copied by --add. Files already in the fixture were left unchanged. |
| `nvd/cve-CVE-2025-57822.json` | snapshot copy | 2026-10-23T09:54:58Z | `db9ef03ac13ed54abe9dbed217ff2acbc8c2f5f7a934ac53179bc1684a52fc14` | none |
| `nvd/cve-CVE-2025-62718.json` | snapshot copy | 2026-10-23T09:55:27Z | `6b1a1a3ce0afca7dd652098acd3090e1527bde886d2d2b903651164112ecd029` | none |
| `nvd/cve-CVE-2026-112390.json` | snapshot copy | 2026-10-23T09:59:03Z | `661a5b25a72efc70b9dc5c9824b5e35a14eac3069dfa33f8be7a78e0b1352b6e` | none |
| `nvd/cve-CVE-2026-112391.json` | snapshot copy | 2026-10-23T09:59:09Z | `16d1819026c6ea83bb8e2ce1573490546ed56262c56fc02fe74bd68c50ed0fa0` | none |
| `nvd/cve-CVE-2026-112392.json` | snapshot copy | 2026-10-23T09:59:15Z | `68837d8f7fd5e3c6dd8994f4dc40143598c2d334db233d0f38cb55a54a91c3a4` | none |
| `nvd/cve-CVE-2026-112394.json` | snapshot copy | 2026-10-23T09:59:27Z | `45a7b50b0677050f4e2a6a4dc56bfc0b934bc8297bb89eba351ec5aea694edf3` | none |
| `nvd/cve-CVE-2026-112397.json` | snapshot copy | 2026-10-23T09:59:39Z | `985f191752e912846054924dbdca4e2868d35af071cbde9d8ec07716469d0215` | none |
| `nvd/cve-CVE-2026-112402.json` | snapshot copy | 2026-10-23T10:00:04Z | `5d061c68cf9d3773876d811f2403b03b6d19290d618ccd529b44c9c0c4c0c304` | none |
| `nvd/cve-CVE-2026-112403.json` | snapshot copy | 2026-10-23T10:00:10Z | `a1283ef8fd3ccb683e3304846e5fb1c464097aff4b30e983f77eb9f7c6ac3d77` | none |
| `nvd/cve-CVE-2026-112896.json` | snapshot copy | 2026-10-23T10:00:57Z | `024251190d2f3ff0f5a40918213ee759518dc3a56dc639a573c6e63d289c2769` | none |
| `nvd/cve-CVE-2026-77078.json` | snapshot copy | 2026-10-23T11:34:24Z | `3582e9112959ef265517dc314d748aef334f0756fb0224925f1f2fa3ed71484e` | none. Copied by --add. Files already in the fixture were left unchanged. |
| `nvd/window-000.json` | snapshot copy, trimmed | 2026-10-23T09:18:29Z | `392ff57a93622188dc7248013f01c5c134516b67e5d2e66dd036ead22e4cc0ab` | vulnerabilities reduced from 2000 to 50: 0 fixture CVEs that appear on this page, plus the first 50 other CVEs in file order. Every other top-level field (resultsPerPage, startIndex, totalResults, format, version, timestamp) is unchanged. |
| `nvd/window-001.json` | snapshot copy, trimmed | 2026-10-23T09:27:18Z | `00e1f6af9dbc68d0355b686cc99b3cc00d1d5ff0667778ba7478bf9aed1449a4` | vulnerabilities reduced from 2000 to 2 (CVE-2022-0778 and CVE-2022-1184), the records in window-001.json.gz whose cpeMatch objects include versionStartExcluding. Every other top-level field is unchanged. Decompressed from the gzip snapshot. |
| `osv/querybatch-000.json` | snapshot copy | 2026-10-23T08:29:53Z | `c3dbdca7bb9a31287aa9ea8ec4b4fb8d4bc0601e163174ccc4a3ba121a6874a3` | none |
| `osv/querybatch-000.request.json` | rebuilt request | 2026-10-23T10:01:04Z | `d5f16685d74e09d539fd8667c3ae2ee89cf72e11ced97748241fb014073a5d3b` | none. POST body rebuilt from the SBOM purls in sorted order, batches of 100, the same construction as fetch_osv. Not a server response. |
| `osv/querybatch-001.json` | snapshot copy | 2026-10-23T08:29:54Z | `b5ca41157f61928e2210de89f8927558c10f226a286ffe2f8db3eaa32d4a63bc` | none |
| `osv/querybatch-001.request.json` | rebuilt request | 2026-10-23T10:01:04Z | `0bd694ca4b3df5827bc4fdd7bd3ecaf8e55e00c538f0441be39e3b41bf7238a6` | none. POST body rebuilt from the SBOM purls in sorted order, batches of 100, the same construction as fetch_osv. Not a server response. |
| `osv/querybatch-002.json` | snapshot copy | 2026-10-23T08:29:55Z | `4405e8f925374226059b740ef83b13d3219980e97269be92ae10c62ca2fdd8b7` | none |
| `osv/querybatch-002.request.json` | rebuilt request | 2026-10-23T10:01:04Z | `914cc8c9c0eda496871e5bfabe41769ec8606a34ef269ca922c7dd0575bff154` | none. POST body rebuilt from the SBOM purls in sorted order, batches of 100, the same construction as fetch_osv. Not a server response. |
| `osv/querybatch-003.json` | snapshot copy | 2026-10-23T08:29:55Z | `faa83f613eacd6c6bdc786bf9790e6c6ce81e77ef893b38e9d3e4c2b216cf929` | none |
| `osv/querybatch-003.request.json` | rebuilt request | 2026-10-23T10:01:04Z | `65cec7abf4612797b5053630e2725217d6d2dd766cf014779be4148eae9f3132` | none. POST body rebuilt from the SBOM purls in sorted order, batches of 100, the same construction as fetch_osv. Not a server response. |
| `osv/vuln-GHSA-22hg-r758-rrw9.json` | snapshot copy | 2026-10-23T08:29:56Z | `3bf68e3cc0dfc49cbd15cd3b5d879dac577247f6a9971801171222c703646027` | none |
| `osv/vuln-GHSA-2328-f5f3-gj25.json` | snapshot copy | 2026-10-23T08:29:56Z | `56c7f1a251a64c65df02015d923acbc24c330f6d9b698863443eb5dbea918af7` | none |
| `osv/vuln-GHSA-239g-whfq-7xj9.json` | snapshot copy | 2026-10-23T08:29:57Z | `dd45de91d2ae0cc30289678eba04a4d83f6959f7a854d64cccb25ddac4328af7` | none |
| `osv/vuln-GHSA-23c5-xmqv-rm74.json` | snapshot copy | 2026-10-23T08:29:57Z | `b600d11977c955f895c5c4fe31791868426ce52685e207783b7585c11eac923f` | none |
| `osv/vuln-GHSA-23hp-3jrh-7fpw.json` | snapshot copy | 2026-10-23T08:29:57Z | `842fd880818c18281fdcea58bb077dbc7f35cc567e2c51445e66bceab4f8c82a` | none |
| `osv/vuln-GHSA-23wx-cgxq-vpwx.json` | snapshot copy | 2026-10-23T08:29:58Z | `1e26e082fdd40257a7ad81662d9017434d5935fb1db31463db8d5fec2824c1fb` | none |
| `osv/vuln-GHSA-248v-346w-9cwc.json` | snapshot copy | 2026-10-23T08:29:58Z | `939695ce05aba967df062661699f9aae251c4dd1db20e5baddeab9e7198945c2` | none |
| `osv/vuln-GHSA-254f-3936-288h.json` | snapshot copy | 2026-10-23T08:29:59Z | `5cad378a1b4368907ce6b63b140231209b7921937e1c3892b0fdcc669a24fd66` | none |
| `osv/vuln-GHSA-27h8-gf7j-v5hc.json` | snapshot copy | 2026-10-23T08:30:00Z | `419ed7fe0271d0c8e75fc93e49afb1bb130777496a9f2c802dda490d5dfbcafb` | none |
| `osv/vuln-GHSA-29mw-wpgm-hmr9.json` | snapshot copy | 2026-10-23T08:30:01Z | `75a505d298d6e520431d9dfdd16773a66dc8df1aa2c0f9775b468568475962aa` | none |
| `osv/vuln-GHSA-2m57-hf25-phgg.json` | snapshot copy | 2026-10-23T08:30:04Z | `49f127e46d03cdaf5f7cf9890fdcdb62d1cb536dabc45767416f8829e98ca177` | none |
| `osv/vuln-GHSA-2mcm-79hx-8fxw.json` | snapshot copy | 2026-10-23T08:30:04Z | `0c4b7639f3263ef8a62cfc8fea2f7424c3b15228205d8d709ffedf70e8950d37` | none |
| `osv/vuln-GHSA-2p57-rm9w-gvfp.json` | snapshot copy | 2026-10-23T08:30:05Z | `1801135a4fa438ad377d1e1f3a7ff50e604185c0f1e1b6e409e92490469e7c8b` | none |
| `osv/vuln-GHSA-33f9-j839-rf8h.json` | snapshot copy | 2026-10-23T08:30:07Z | `1797f9b7d53e5af63f279bf67c2f67120d58c89f328b2497374dd7795e8052a1` | none |
| `osv/vuln-GHSA-35jh-r3h4-6jhm.json` | snapshot copy | 2026-10-23T08:30:10Z | `1cee82c254d58a08d607beb6930b1d2713d7d2206f2e355dd432f0db74f8b915` | none |
| `osv/vuln-GHSA-37ch-88jc-xwx2.json` | snapshot copy | 2026-10-23T08:30:10Z | `3d7538c8cb7654f5a1769f9b3e97f8bfccc87f63a6c90e8301aab83c042cb16a` | none |
| `osv/vuln-GHSA-3h52-269p-cp9r.json` | snapshot copy | 2026-10-23T08:30:13Z | `3a7ade8818316aa3557af863de256251b2bc4e176b089cb804491e31d19186e9` | none |
| `osv/vuln-GHSA-3h5v-q93c-6h6q.json` | snapshot copy | 2026-10-23T08:30:13Z | `6c8390017c6a83310c4e816ff9f8e4eac2e73be590487a9516fb808e7d30a76d` | none |
| `osv/vuln-GHSA-3jfq-g458-7qm9.json` | snapshot copy | 2026-10-23T08:30:14Z | `c2014c5433b34841f1edb7ac5274e8200353d056e2f9ff7e80f364f39ac47c6e` | none |
| `osv/vuln-GHSA-3p68-rc4w-qgx5.json` | snapshot copy | 2026-10-23T08:30:14Z | `b5b1a930c6cf1d63545e083f740c490d7fd8240e35832c8ab03f40c4c2b024ed` | none |
| `osv/vuln-GHSA-3rfm-jhwj-7488.json` | snapshot copy | 2026-10-23T08:30:15Z | `361fff7afbcdf118dcf53b3cc111555e8be1861cc7297f84063d839fe9f9298c` | none |
| `osv/vuln-GHSA-4342-x723-ch2f.json` | snapshot copy | 2026-10-23T08:30:18Z | `2dce514a407ba2732e666c153531953ebd7eeca54c353e54d0709bf1583e5808` | none |
| `osv/vuln-GHSA-4558-3h8r-v8xp.json` | snapshot copy | 2026-10-23T08:30:19Z | `b77a6c99e6d8a5977cc96c81e31330a6bb09cba7b706d2e42b7d173ec43c3c64` | none |
| `osv/vuln-GHSA-58r4-6rv3-gfh8.json` | snapshot copy | 2026-10-23T08:30:27Z | `dc717400a27305f85c8186f5ad536e6e9f7d80e2065db611360bfed79d9bfe3c` | none |
| `osv/vuln-GHSA-6rw7-vpxm-498p.json` | snapshot copy | 2026-10-23T08:30:41Z | `1ae87f01adb980c21c276761b38bf4c59e62fc6095237d1b5f6a9da77bee893e` | none |
| `osv/vuln-GHSA-7gfc-8cq8-jh5f.json` | snapshot copy | 2026-10-23T08:30:45Z | `71f81c5bbc10d1c9066806bdffc6d3faea2826cc979109b472a3f5ec43388196` | none |
| `osv/vuln-GHSA-7m27-7ghc-44w9.json` | snapshot copy | 2026-10-23T08:30:46Z | `5844ae28156b37252dab7ae8d1ec861d613c0548bbb2f70b912402757a0f9559` | none |
| `osv/vuln-GHSA-7mwm-ghpf-9vrm.json` | snapshot copy | 2026-10-23T08:30:47Z | `ab8e527d9de7544767d72d034d4c3757016f51b8cf304fa2cb89f9140b9b9c14` | none |
| `osv/vuln-GHSA-8cf7-32gw-wr33.json` | snapshot copy | 2026-10-23T08:30:51Z | `e72bb9b159a435c4cd9d8e9a1bebdd913a8967a8c94d348d1f259a96ca96eecc` | none |
| `osv/vuln-GHSA-8g5g-8vmr-9782.json` | snapshot copy | 2026-10-23T08:30:52Z | `52ed3aa32e563b0afe93b8035cf21250791023068779230d970e7ad5b4396664` | none |
| `osv/vuln-GHSA-952p-6rrq-rcjv.json` | snapshot copy | 2026-10-23T08:30:58Z | `24908d0bd1173194d31ee935154dd51c7debd09c1a10625d49cec3e75db32a02` | none |
| `osv/vuln-GHSA-9965-vmph-33xx.json` | snapshot copy | 2026-10-23T08:31:01Z | `4e3b067c31b6d693ab760b595515c3d258bec378c6816fca85c16f48f82a6efd` | none. Copied by --add. Files already in the fixture were left unchanged. |
| `osv/vuln-GHSA-9hjg-9r4m-mvj7.json` | snapshot copy | 2026-10-23T08:31:03Z | `15aca2f0fc13827fb0a2d327adb643c3c81c77c2cb3fad962ae290ee83abea70` | none |
| `osv/vuln-GHSA-c36v-fmgq-m8hx.json` | snapshot copy | 2026-10-23T08:31:08Z | `7ffaf4035c377bcba157d8b03eae558bd04965a380cb875199579c129f129251` | none. Added because the severity vector is CVSS:3.0. The earlier OSV fixtures had no 3.0 vector. |
| `osv/vuln-GHSA-j7hp-h8jx-5ppr.json` | snapshot copy | 2026-10-23T08:31:38Z | `51a4b88c551207cc84df6411f15a72f4b37ec7705b52364516a9b346c656b9b8` | none |
| `osv/vuln-GHSA-pchr-8j38-3x4p.json` | snapshot copy | 2026-10-23T08:31:55Z | `141b99922266585d2bce837dd3b72169e1f4e149204354534876c55f005559cb` | none |
| `osv/vuln-GHSA-wc9g-mqfw-jrwm.json` | snapshot copy | 2026-10-23T08:32:28Z | `32686c0aed2a0e7e3ac7962e9623baf65f600c796778c3b83c5ae010b041997f` | none. Copied by --add. Files already in the fixture were left unchanged. |
| `osv/vuln-GHSA-wf5p-g6vw-rhxx.json` | snapshot copy | 2026-10-23T08:32:28Z | `321da1b5d1e5755c641bb8e1fce56bb7e9e8487f0b7652c30acb469474244bb3` | none. Copied by --add. Files already in the fixture were left unchanged. |
| `osv/vuln-PYSEC-2021-142.json` | snapshot copy | 2026-10-23T08:32:37Z | `f40e07bbe3a7b9f3f25b72f88e7dbc85f9aa5ef27e2cef570472d07421f3aea7` | none |
| `osv/vuln-PYSEC-2023-161.json` | snapshot copy | 2026-10-23T08:32:37Z | `53a81b065eab7793eb366ecf04feeea3ceffb6c520ae1a549011532b1d0d1c0f` | none |
| `osv/vuln-PYSEC-2024-230.json` | snapshot copy | 2026-10-23T08:32:44Z | `a6024410fa4bd00afb15bf94a5326efe91b730f65cf1347da4c8e4fe8b4037fe` | none |
| `osv/vuln-PYSEC-2026-1794.json` | snapshot copy | 2026-10-23T08:33:05Z | `ad9f1ddf693a976216b0db82af008d83ca01189d83fba03357328b376c1bd7b1` | none |
| `osv/vuln-PYSEC-2026-1872.json` | snapshot copy | 2026-10-23T08:33:06Z | `aaf80fba462800e5f9ab583bc6b633b2f95423c2e27ef821bf5ebd1fef9ad9c8` | none |
| `osv/vuln-PYSEC-2026-3982.json` | snapshot copy | 2026-10-23T08:33:43Z | `4b236e228b792479a1301102034539f583a6460746adc55b3d490dde72a5bc08` | none |
