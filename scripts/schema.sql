-- Sibyl Postgres schemas. Column lists match docs/project/data.md.
-- scripts/seed_db.py applies this file, then upserts Acme from the SBOMs.
-- The Zetaris check inserts and deletes its own probe row.

CREATE SCHEMA IF NOT EXISTS acme_internal;
CREATE SCHEMA IF NOT EXISTS evidence;

CREATE TABLE IF NOT EXISTS acme_internal.services (
    service_id text PRIMARY KEY,
    name text NOT NULL,
    team text NOT NULL,
    internet_facing boolean NOT NULL,
    criticality real NOT NULL,
    data_class text NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_internal.sboms (
    sbom_id text PRIMARY KEY,
    service_id text NOT NULL REFERENCES acme_internal.services (service_id),
    format text NOT NULL,
    generated_at timestamptz NOT NULL,
    source_lockfile text NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_internal.components (
    component_id text PRIMARY KEY,
    sbom_id text NOT NULL REFERENCES acme_internal.sboms (sbom_id),
    purl text NOT NULL,
    ecosystem text NOT NULL,
    name text NOT NULL,
    version text NOT NULL,
    direct boolean NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence.source_records (
    record_id text PRIMARY KEY,
    source text NOT NULL,
    source_id text NOT NULL,
    retrieved_at timestamptz NOT NULL,
    status text NOT NULL,
    raw_json jsonb NOT NULL,
    content_hash text NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence.vuln_aliases (
    vuln_id text NOT NULL,
    alias_id text NOT NULL,
    source text NOT NULL,
    PRIMARY KEY (vuln_id, alias_id, source)
);

CREATE TABLE IF NOT EXISTS evidence.affected (
    record_id text NOT NULL REFERENCES evidence.source_records (record_id),
    vuln_id text NOT NULL,
    ecosystem text NOT NULL,
    package text NOT NULL,
    range_type text NOT NULL,
    introduced text,
    fixed text,
    last_affected text,
    raw_range text,
    PRIMARY KEY (record_id, vuln_id, ecosystem, package, range_type)
);

CREATE TABLE IF NOT EXISTS evidence.severities (
    record_id text NOT NULL REFERENCES evidence.source_records (record_id),
    vuln_id text NOT NULL,
    source text NOT NULL,
    vector text,
    score real,
    version text,
    PRIMARY KEY (record_id, vuln_id, source)
);

CREATE TABLE IF NOT EXISTS evidence.runs (
    run_id text PRIMARY KEY,
    started_at timestamptz NOT NULL,
    config jsonb NOT NULL,
    status text NOT NULL,
    budget jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence.run_events (
    event_id text PRIMARY KEY,
    run_id text NOT NULL REFERENCES evidence.runs (run_id),
    ts timestamptz NOT NULL,
    actor text NOT NULL,
    type text NOT NULL,
    payload jsonb NOT NULL
);
