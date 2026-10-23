-- Fixed-URL REST tables. Headers use {{CONTACT_EMAIL}} from .env.
-- EPSS is one URL with the frozen-fixture CVE ids (38, under the 100 limit).
-- EUVD is the unpaged latest-exploited list.

CREATE LIGHTNING REST TABLE kev_catalog FROM sibyl_public REQUEST(
  endpoint "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  method "get",
  response_type "json",
  http_encoding "URLENCODED"
) HEADER (
  user-agent "sibyl {{CONTACT_EMAIL}}"
) BODY ();

CREATE LIGHTNING REST TABLE euvd_exploited FROM sibyl_public REQUEST(
  endpoint "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities",
  method "get",
  response_type "json",
  http_encoding "URLENCODED"
) HEADER (
  user-agent "sibyl {{CONTACT_EMAIL}}"
) BODY ();

CREATE LIGHTNING REST TABLE epss_batch FROM sibyl_public REQUEST(
  endpoint "https://api.first.org/data/v1/epss?cve=CVE-2020-14343,CVE-2020-28500,CVE-2021-23337,CVE-2021-23436,CVE-2021-32804,CVE-2022-23539,CVE-2022-25645,CVE-2022-37603,CVE-2023-40590,CVE-2023-4863,CVE-2023-5129,CVE-2024-29415,CVE-2024-37890,CVE-2024-39689,CVE-2024-4067,CVE-2024-4340,CVE-2024-45296,CVE-2024-47081,CVE-2024-51479,CVE-2024-56332,CVE-2025-13473,CVE-2025-15284,CVE-2025-48068,CVE-2025-57822,CVE-2025-62718,CVE-2026-112390,CVE-2026-112391,CVE-2026-112392,CVE-2026-112394,CVE-2026-112397,CVE-2026-112402,CVE-2026-112403,CVE-2026-112896,CVE-2026-27904,CVE-2026-33896,CVE-2026-4867,CVE-2026-59873,CVE-2026-87817",
  method "get",
  response_type "json",
  http_encoding "URLENCODED"
) HEADER (
  user-agent "sibyl {{CONTACT_EMAIL}}"
) BODY ();
