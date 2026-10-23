-- Lightning database for the public vulnerability feeds.
-- One statement per REST call. scripts/apply_zetaris_sql.py submits each one.

CREATE LIGHTNING DATABASE sibyl_public DESCRIBE BY "Sibyl public vulnerability feeds";
