"""Create the `inventory` schema, and move the old sample tables into it.

Older databases kept the sample tables in `acme_internal`, named after the
sample company the product no longer shows.
Those tables are moved (not copied) into `inventory`, their services become
the demo workspace, and the old schema is dropped once it is empty. Running
this twice changes nothing.
"""

from __future__ import annotations

import psycopg

DEMO_WORKSPACE = "sample"
DEMO_NAME = "Sample workspace"
_LEGACY = "acme_internal"

_MOVE = f"""
DO $$
DECLARE
  name text;
BEGIN
  FOREACH name IN ARRAY ARRAY['services', 'sboms', 'components'] LOOP
    IF to_regclass('{_LEGACY}.' || name) IS NOT NULL AND to_regclass('inventory.' || name) IS NULL THEN
      EXECUTE format('ALTER TABLE {_LEGACY}.%I SET SCHEMA inventory', name);
    END IF;
  END LOOP;
END $$;
"""

_TABLES = """
CREATE TABLE IF NOT EXISTS inventory.workspaces (
    workspace_id text PRIMARY KEY,
    name text NOT NULL,
    is_demo boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    settings jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS inventory.repositories (
    repo_id text PRIMARY KEY,
    workspace_id text NOT NULL REFERENCES inventory.workspaces (workspace_id) ON DELETE CASCADE,
    kind text NOT NULL,
    location text NOT NULL,
    branch text NOT NULL DEFAULT 'main',
    token_env text NOT NULL DEFAULT '',
    sync_interval_minutes integer NOT NULL DEFAULT 60,
    last_scanned_sha text,
    last_synced_at timestamptz,
    status text NOT NULL DEFAULT 'new',
    error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS inventory.services (
    service_id text PRIMARY KEY,
    name text NOT NULL,
    team text NOT NULL DEFAULT '',
    internet_facing boolean NOT NULL DEFAULT false,
    criticality real NOT NULL DEFAULT 0.5,
    data_class text NOT NULL DEFAULT 'internal'
);

CREATE TABLE IF NOT EXISTS inventory.sboms (
    sbom_id text PRIMARY KEY,
    service_id text NOT NULL REFERENCES inventory.services (service_id),
    format text NOT NULL,
    generated_at timestamptz NOT NULL,
    source_lockfile text NOT NULL
);

CREATE TABLE IF NOT EXISTS inventory.components (
    component_id text PRIMARY KEY,
    sbom_id text NOT NULL REFERENCES inventory.sboms (sbom_id),
    purl text NOT NULL,
    ecosystem text NOT NULL,
    name text NOT NULL,
    version text NOT NULL,
    direct boolean NOT NULL
);

ALTER TABLE inventory.services ADD COLUMN IF NOT EXISTS workspace_id text;
ALTER TABLE inventory.services ADD COLUMN IF NOT EXISTS repo_id text;
ALTER TABLE inventory.services ADD COLUMN IF NOT EXISTS path text NOT NULL DEFAULT '';
ALTER TABLE inventory.services ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';
ALTER TABLE inventory.services ADD COLUMN IF NOT EXISTS triage_policy text NOT NULL DEFAULT 'interval';
ALTER TABLE inventory.services ADD COLUMN IF NOT EXISTS triage_interval_minutes integer NOT NULL DEFAULT 1440;
ALTER TABLE inventory.services ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE inventory.services ALTER COLUMN team SET DEFAULT '';
ALTER TABLE inventory.services ALTER COLUMN data_class SET DEFAULT 'internal';
ALTER TABLE inventory.sboms ADD COLUMN IF NOT EXISTS commit_sha text;
ALTER TABLE inventory.components ADD COLUMN IF NOT EXISTS source_file text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS inventory.questions (
    question_id text PRIMARY KEY,
    workspace_id text NOT NULL REFERENCES inventory.workspaces (workspace_id) ON DELETE CASCADE,
    service_id text,
    repo_id text,
    kind text NOT NULL,
    field text NOT NULL DEFAULT '',
    prompt text NOT NULL,
    proposed jsonb,
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    confidence real NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'open',
    answer jsonb,
    answered_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    answered_at timestamptz
);

CREATE TABLE IF NOT EXISTS inventory.repo_syncs (
    sync_id text PRIMARY KEY,
    repo_id text NOT NULL REFERENCES inventory.repositories (repo_id) ON DELETE CASCADE,
    workspace_id text NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    from_sha text,
    to_sha text,
    mode text NOT NULL DEFAULT 'full',
    status text NOT NULL DEFAULT 'running',
    summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    error text NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS services_workspace ON inventory.services (workspace_id);
CREATE INDEX IF NOT EXISTS questions_open ON inventory.questions (workspace_id, status);
CREATE INDEX IF NOT EXISTS syncs_repo ON inventory.repo_syncs (repo_id, started_at);
"""

# Services from before workspaces existed are the sample services: they become the demo workspace.
_ADOPT_WORKSPACE = """
INSERT INTO inventory.workspaces (workspace_id, name, is_demo)
SELECT %s, %s, true
WHERE EXISTS (SELECT 1 FROM inventory.services WHERE workspace_id IS NULL)
ON CONFLICT (workspace_id) DO NOTHING
"""
_ADOPT_SERVICES = "UPDATE inventory.services SET workspace_id = %s WHERE workspace_id IS NULL"

_CONSTRAINTS = """
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'services_workspace_fk') THEN
    ALTER TABLE inventory.services
      ADD CONSTRAINT services_workspace_fk FOREIGN KEY (workspace_id)
      REFERENCES inventory.workspaces (workspace_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'services_repo_fk') THEN
    ALTER TABLE inventory.services
      ADD CONSTRAINT services_repo_fk FOREIGN KEY (repo_id)
      REFERENCES inventory.repositories (repo_id) ON DELETE SET NULL;
  END IF;
END $$;
ALTER TABLE inventory.services ALTER COLUMN workspace_id SET NOT NULL;
"""

_DROP_LEGACY = f"""
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = '{_LEGACY}')
     AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = '{_LEGACY}') THEN
    EXECUTE 'DROP SCHEMA {_LEGACY}';
  END IF;
END $$;
"""


def ensure_inventory_schema(conn: psycopg.Connection) -> None:
    conn.execute("CREATE SCHEMA IF NOT EXISTS inventory")
    conn.execute(_MOVE)
    conn.execute(_TABLES)
    conn.execute(_ADOPT_WORKSPACE, (DEMO_WORKSPACE, DEMO_NAME))
    conn.execute(_ADOPT_SERVICES, (DEMO_WORKSPACE,))
    conn.execute(_CONSTRAINTS)
    conn.execute(_DROP_LEGACY)
