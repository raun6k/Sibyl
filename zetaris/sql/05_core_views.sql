-- One row per service, component, source vulnerability, and source range.
-- Version checks stay in Python. Do not filter VERSIONS rows by string
-- equality: 1.0 and 1.0.0 are the same version.
-- Each feed view is joined once. v_epss may itself be a UNION ALL of
-- epss_batch_000, epss_batch_001, ... Joining that view twice is the
-- Zetaris self-join limit; this query references it once.
-- A CVE id is the affected vuln id when that id is already a CVE,
-- otherwise a CVE alias stated by the same source.

CREATE SCHEMASTORE CONTAINER sibyl;

CREATE OR REPLACE SCHEMASTORE VIEW v_candidate_matches WITH CONTAINER sibyl AS
SELECT
  matches.service_id,
  matches.service_name,
  matches.team,
  matches.internet_facing,
  matches.criticality,
  matches.data_class,
  matches.component_id,
  matches.purl,
  matches.ecosystem,
  matches.package,
  matches.version,
  matches.direct,
  matches.record_id,
  matches.source,
  matches.record_status,
  matches.vuln_id,
  matches.range_type,
  matches.introduced,
  matches.fixed,
  matches.last_affected,
  matches.raw_range,
  matches.range_index,
  matches.cve_id,
  kev.date_added AS kev_date_added,
  kev.due_date AS kev_due_date,
  kev.ransomware AS kev_ransomware,
  euvd.euvd_id,
  euvd.epss AS euvd_epss,
  epss.epss AS epss,
  epss.percentile AS epss_percentile
FROM (
  SELECT
    services.service_id,
    services.name AS service_name,
    services.team,
    services.internet_facing,
    services.criticality,
    services.data_class,
    components.component_id,
    components.purl,
    components.ecosystem,
    components.name AS package,
    components.version,
    components.direct,
    affected.record_id,
    source_records.source,
    source_records.status AS record_status,
    affected.vuln_id,
    affected.range_type,
    affected.introduced,
    affected.fixed,
    affected.last_affected,
    affected.raw_range,
    affected.range_index,
    CASE
      WHEN affected.vuln_id LIKE 'CVE-%' THEN affected.vuln_id
      ELSE vuln_aliases.alias_id
    END AS cve_id,
    row_number() OVER (
      PARTITION BY components.component_id, affected.record_id, affected.range_index, affected.range_type
      ORDER BY CASE
        WHEN affected.vuln_id LIKE 'CVE-%' THEN affected.vuln_id
        ELSE vuln_aliases.alias_id
      END
    ) AS cve_rank
  FROM acme_internal.components AS components
  JOIN acme_internal.sboms AS sboms
    ON components.sbom_id = sboms.sbom_id
  JOIN acme_internal.services AS services
    ON sboms.service_id = services.service_id
  JOIN evidence.affected AS affected
    ON affected.ecosystem = components.ecosystem
   AND affected.package = components.name
  JOIN evidence.source_records AS source_records
    ON source_records.record_id = affected.record_id
  LEFT JOIN evidence.vuln_aliases AS vuln_aliases
    ON vuln_aliases.vuln_id = affected.vuln_id
   AND vuln_aliases.alias_id LIKE 'CVE-%'
) matches
LEFT JOIN sibyl_feeds.v_kev kev
  ON kev.cve_id = matches.cve_id
LEFT JOIN sibyl_feeds.v_euvd_exploited euvd
  ON euvd.cve_id = matches.cve_id
LEFT JOIN sibyl_feeds.v_epss epss
  ON epss.cve_id = matches.cve_id
WHERE matches.cve_rank = 1;
