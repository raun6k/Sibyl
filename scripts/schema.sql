-- Sibyl Postgres schemas. Column lists match docs/project/data.md.
-- scripts/seed_db.py applies this file. Probe rows are stand-ins until the P2 seed.

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

INSERT INTO acme_internal.services (service_id, name, team, internet_facing, criticality, data_class)
VALUES
    ('checkout-api', 'checkout-api', 'payments', true, 1.0, 'cardholder'),
    ('reporting-worker', 'reporting-worker', 'data', false, 0.5, 'internal')
ON CONFLICT (service_id) DO NOTHING;

INSERT INTO acme_internal.sboms (sbom_id, service_id, format, generated_at, source_lockfile)
VALUES
    ('sbom-checkout-api', 'checkout-api', 'cyclonedx', '2026-10-23 00:00:00+00', 'requirements.txt')
ON CONFLICT (sbom_id) DO NOTHING;

INSERT INTO acme_internal.components (component_id, sbom_id, purl, ecosystem, name, version, direct)
VALUES
    ('comp-django', 'sbom-checkout-api', 'pkg:pypi/django@4.2.0', 'pypi', 'django', '4.2.0', true),
    ('comp-requests', 'sbom-checkout-api', 'pkg:pypi/requests@2.31.0', 'pypi', 'requests', '2.31.0', true),
    ('comp-pyyaml', 'sbom-checkout-api', 'pkg:pypi/pyyaml@5.4.1', 'pypi', 'pyyaml', '5.4.1', false)
ON CONFLICT (component_id) DO NOTHING;

INSERT INTO evidence.source_records (record_id, source, source_id, retrieved_at, status, raw_json, content_hash)
VALUES
    ('rec-probe-1', 'osv', 'PROBE-OSV-1', '2026-10-23 00:00:00+00', 'active', '{"probe": true}', 'probe-1')
ON CONFLICT (record_id) DO NOTHING;

INSERT INTO evidence.affected (record_id, vuln_id, ecosystem, package, range_type, introduced, fixed, last_affected, raw_range)
VALUES
    ('rec-probe-1', 'CVE-PROBE-0001', 'pypi', 'django', 'ECOSYSTEM', '0', '4.2.14', NULL, '<4.2.14')
ON CONFLICT (record_id, vuln_id, ecosystem, package, range_type) DO NOTHING;
