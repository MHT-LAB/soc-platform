#!/bin/bash
# First start only (the image runs these when the data directory is empty).
# Creates the owner role and the database. The service roles (soc_app,
# soc_ingest, soc_ingest_writer) are created NOLOGIN by the first migration;
# `python -m soc_api.db deploy` gives soc_ingest its login afterwards.
#
# The owner password arrives in the container's environment (db.env) and goes to
# psql as a variable, never through shell text. The session is told not to log
# the failing statement, so the password cannot end up in the server log.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --no-psqlrc --username postgres --dbname postgres \
  -v owner_password="${SOC_DB_OWNER_PASSWORD:?SOC_DB_OWNER_PASSWORD is not set}" <<'SQL'
SET log_min_error_statement = 'panic';
CREATE ROLE soc_owner LOGIN CREATEROLE NOSUPERUSER NOCREATEDB NOBYPASSRLS
  PASSWORD :'owner_password';
CREATE DATABASE soc OWNER soc_owner;
-- Service roles log in to soc only.
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
SQL
