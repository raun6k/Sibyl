-- Fixed-URL REST tables. Headers use {{CONTACT_EMAIL}} from .env.
-- {{EPSS_CVES}} is the matched CVE set: distinct CVE ids from the same
-- component × affected × vuln_aliases join as v_candidate_matches, read
-- from Postgres by apply_zetaris_sql.py. At most 100 ids go in one URL.
-- Over 100, that script repeats this statement as epss_batch_000,
-- epss_batch_001, ... and v_epss reads them with one UNION ALL.

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

CREATE LIGHTNING REST TABLE epss_batch_000 FROM sibyl_public REQUEST(
  endpoint "https://api.first.org/data/v1/epss?cve={{EPSS_CVES}}",
  method "get",
  response_type "json",
  http_encoding "URLENCODED"
) HEADER (
  user-agent "sibyl {{CONTACT_EMAIL}}"
) BODY ();
