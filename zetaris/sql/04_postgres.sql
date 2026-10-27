-- Register Sibyl Postgres with Zetaris.
-- Lightning SQL, one statement per call. scripts/apply_zetaris_sql.py
-- fills the placeholders from .env and submits each statement to
-- POST /sql-editor/sqls/run.
--
-- The query engine runs in Docker, so the host is the engine's view of this
-- machine (host.docker.internal), not localhost. The schema option is required:
-- without it, JDBC metadata lookup only sees public, and these tables live in
-- inventory and evidence.
--
-- {{PG_HOST}} {{PG_PORT}} {{PG_USER}} {{PG_PASSWORD}} {{PG_DATABASE}}

-- The sample tables used to live in their own datasource. Drop it; the
-- views that read it are rebuilt by 05_core_views.sql.
DROP DATASOURCE acme_internal;

CREATE DATASOURCE inventory DESCRIBE BY "Sibyl inventory" OPTIONS (
  jdbcdriver "org.postgresql.Driver",
  jdbcurl "jdbc:postgresql://{{PG_HOST}}:{{PG_PORT}}/{{PG_DATABASE}}",
  username "{{PG_USER}}",
  password "{{PG_PASSWORD}}",
  fetchsize "1000",
  schema "inventory"
);

REGISTER DATASOURCE TABLE "workspaces" FROM inventory;

REGISTER DATASOURCE TABLE "repositories" FROM inventory;

REGISTER DATASOURCE TABLE "services" FROM inventory;

REGISTER DATASOURCE TABLE "sboms" FROM inventory;

REGISTER DATASOURCE TABLE "components" FROM inventory;

CREATE DATASOURCE evidence DESCRIBE BY "Sibyl evidence" OPTIONS (
  jdbcdriver "org.postgresql.Driver",
  jdbcurl "jdbc:postgresql://{{PG_HOST}}:{{PG_PORT}}/{{PG_DATABASE}}",
  username "{{PG_USER}}",
  password "{{PG_PASSWORD}}",
  fetchsize "1000",
  schema "evidence"
);

REGISTER DATASOURCE TABLE "source_records" FROM evidence;

REGISTER DATASOURCE TABLE "vuln_aliases" FROM evidence;

REGISTER DATASOURCE TABLE "affected" FROM evidence;

REGISTER DATASOURCE TABLE "severities" FROM evidence;

REGISTER DATASOURCE TABLE "runs" FROM evidence;

REGISTER DATASOURCE TABLE "run_events" FROM evidence;

-- World Model case state (P10). The API also creates this on first use (sibyl.inventory.usl).
CREATE DATASOURCE world DESCRIBE BY "Sibyl World Model state" OPTIONS (
  jdbcdriver "org.postgresql.Driver",
  jdbcurl "jdbc:postgresql://{{PG_HOST}}:{{PG_PORT}}/{{PG_DATABASE}}",
  username "{{PG_USER}}",
  password "{{PG_PASSWORD}}",
  fetchsize "1000",
  schema "world"
);

REGISTER DATASOURCE TABLE "case_state" FROM world;
