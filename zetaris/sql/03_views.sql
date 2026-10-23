-- Flatten the public feeds to one row per CVE.
-- EUVD's REST table is already one row per exploited record (the endpoint
-- returns a JSON array). aliases is one newline-separated string.
-- KEV and EPSS are one JSON object with an array inside.
-- Numeric strings are cast. Run REFRESH after an evidence column change
-- so JDBC metadata sees range_index.

REFRESH DATASOURCE TABLES FROM evidence;

CREATE SCHEMASTORE CONTAINER sibyl_feeds;

CREATE SCHEMASTORE VIEW v_kev WITH CONTAINER sibyl_feeds AS
SELECT
  vuln.`cveID` AS cve_id,
  vuln.dateAdded AS date_added,
  vuln.dueDate AS due_date,
  vuln.knownRansomwareCampaignUse AS ransomware
FROM sibyl_public.kev_catalog
LATERAL VIEW explode(vulnerabilities) AS vuln;

CREATE SCHEMASTORE VIEW v_epss WITH CONTAINER sibyl_feeds AS
SELECT
  item.cve AS cve_id,
  CAST(item.epss AS DOUBLE) AS epss,
  CAST(item.percentile AS DOUBLE) AS percentile
FROM sibyl_public.epss_batch
LATERAL VIEW explode(data) AS item;

CREATE SCHEMASTORE VIEW v_euvd_exploited WITH CONTAINER sibyl_feeds AS
SELECT
  id AS euvd_id,
  trim(alias_id) AS cve_id,
  CAST(baseScore AS DOUBLE) AS base_score,
  baseScoreVersion AS base_score_version,
  CAST(epss AS DOUBLE) AS epss,
  exploitedSince AS exploited_since
FROM sibyl_public.euvd_exploited
LATERAL VIEW explode(split(aliases, '\n')) AS alias_id
WHERE trim(alias_id) LIKE 'CVE-%';

CACHE TABLE sibyl_public.kev_catalog;

CACHE TABLE sibyl_public.euvd_exploited;

CACHE TABLE sibyl_public.epss_batch;

CACHE TABLE sibyl_feeds.v_kev;

CACHE TABLE sibyl_feeds.v_euvd_exploited;

CACHE TABLE sibyl_feeds.v_epss;
