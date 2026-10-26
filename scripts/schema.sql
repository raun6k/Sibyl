-- Sibyl Postgres evidence schema. Column lists match docs/project/data.md.
-- The inventory schema (workspaces, repositories, services, SBOMs, components,
-- questions, syncs) is created by sibyl.inventory.schema.ensure_inventory_schema.
-- scripts/seed_db.py applies both, then upserts the demo workspace from the SBOMs.
-- The Zetaris check inserts and deletes its own probe row.

CREATE SCHEMA IF NOT EXISTS evidence;

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
    range_index integer NOT NULL DEFAULT 0,
    PRIMARY KEY (record_id, vuln_id, ecosystem, package, range_type, range_index)
);

CREATE TABLE IF NOT EXISTS evidence.severities (
    record_id text NOT NULL REFERENCES evidence.source_records (record_id),
    vuln_id text NOT NULL,
    source text NOT NULL,
    vector text,
    score real,
    version text NOT NULL DEFAULT '',
    PRIMARY KEY (record_id, vuln_id, source, version)
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
