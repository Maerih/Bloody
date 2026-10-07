#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# First-boot initialisation for the development Postgres (docker-entrypoint-initdb.d).
# Mirrors the production role model (docs/adr/0002):
#   bloody_owner  owns the schema; used ONLY by migrations (DATABASE_MIGRATION_URL)
#   bloody_app    runtime role of the API: DML only, NOBYPASSRLS and not a table owner, so
#                 row-level security (app.tenant_id) is always enforced for it
#   keycloak      optional SSO profile database
# Databases: bloody (application), bloody_test (vitest integration tests), keycloak.
set -eu

: "${BLOODY_DB_OWNER_PASSWORD:?}"
: "${BLOODY_DB_APP_PASSWORD:?}"
: "${KEYCLOAK_DB_PASSWORD:?}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v owner_pw="$BLOODY_DB_OWNER_PASSWORD" -v app_pw="$BLOODY_DB_APP_PASSWORD" -v kc_pw="$KEYCLOAK_DB_PASSWORD" <<'SQL'
CREATE ROLE bloody_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'owner_pw';
CREATE ROLE bloody_app   LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT
  CONNECTION LIMIT 300 PASSWORD :'app_pw';
CREATE ROLE keycloak     LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'kc_pw';

-- Safety net for the runtime role: bounded statements, no idle transactions holding locks.
ALTER ROLE bloody_app SET statement_timeout = '30s';
ALTER ROLE bloody_app SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE bloody_app SET lock_timeout = '10s';

ALTER DATABASE bloody OWNER TO bloody_owner;
CREATE DATABASE bloody_test OWNER bloody_owner;
CREATE DATABASE keycloak OWNER keycloak;
REVOKE ALL ON DATABASE bloody, bloody_test FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE bloody, bloody_test TO bloody_app;
SQL

for db in bloody bloody_test; do
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db" <<'SQL'
-- Superuser-only extensions are created here; migrations may CREATE EXTENSION IF NOT EXISTS.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

ALTER SCHEMA public OWNER TO bloody_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO bloody_app;

-- Everything bloody_owner creates later (via migrations) is usable — but not owned — by the app.
ALTER DEFAULT PRIVILEGES FOR ROLE bloody_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bloody_app;
ALTER DEFAULT PRIVILEGES FOR ROLE bloody_owner IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO bloody_app;
ALTER DEFAULT PRIVILEGES FOR ROLE bloody_owner IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO bloody_app;
SQL
done

echo "bloody: roles bloody_owner / bloody_app / keycloak and databases bloody, bloody_test, keycloak initialised"
