-- Register Sibyl Postgres with Zetaris.
-- Lightning SQL, one statement per call. scripts/apply_zetaris_sql.py
-- fills the placeholders from .env and submits each statement to
-- POST /sql-editor/sqls/run.
--
-- The query engine runs in Docker, so the host is the engine's view of this
-- machine (host.docker.internal), not localhost. The schema option is required:
-- without it, JDBC metadata lookup only sees public, and these tables live in
-- acme_internal and evidence.
--
-- {{PG_HOST}} {{PG_PORT}} {{PG_USER}} {{PG_PASSWORD}} {{PG_DATABASE}}

CREATE DATASOURCE acme_internal DESCRIBE BY "Sibyl acme_internal" OPTIONS (
  jdbcdriver "org.postgresql.Driver",
  jdbcurl "jdbc:postgresql://{{PG_HOST}}:{{PG_PORT}}/{{PG_DATABASE}}",
  username "{{PG_USER}}",
  password "{{PG_PASSWORD}}",
  fetchsize "1000",
  schema "acme_internal"
);

REGISTER DATASOURCE TABLE "services" FROM acme_internal;

REGISTER DATASOURCE TABLE "sboms" FROM acme_internal;

REGISTER DATASOURCE TABLE "components" FROM acme_internal;

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
