#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# First-boot initialisation for the development Postgres (docker-entrypoint-initdb.d).
# Mirrors the production role model (docs/adr/0002):
#   bloody_owner  owns the schema; used ONLY by the migration runner (its DATABASE_URL)
#   bloody_app    runtime role of the API (DATABASE_APP_URL): DML only, NOBYPASSRLS and not a
#                 table owner, so row-level security (app.tenant_id) is always enforced for it.
#                 Password = BLOODY_APP_DB_PASSWORD, the variable the API itself reads.
#   keycloak      optional SSO profile database
# Databases: bloody (application), bloody_test (vitest integration tests), keycloak.
set -eu

: "${BLOODY_OWNER_DB_PASSWORD:?}"
: "${BLOODY_APP_DB_PASSWORD:?}"
: "${KEYCLOAK_DB_PASSWORD:?}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v owner_pw="$BLOODY_OWNER_DB_PASSWORD" -v app_pw="$BLOODY_APP_DB_PASSWORD" -v kc_pw="$KEYCLOAK_DB_PASSWORD" <<'SQL'
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

-- Deliberately NO "ALTER DEFAULT PRIVILEGES … TO bloody_app": the migration runner
-- (apps/api/src/db/migrate.ts applyGrants) is the single authority on the runtime role's grants
-- (append-only audit_log, read-only auth_lookup, no direct access to partitions, EXECUTE only on
-- the functions it names). Default privileges would silently widen that, e.g. make every future
-- SECURITY DEFINER function callable by bloody_app even after a migration revokes it from PUBLIC.
SQL
done

echo "bloody: roles bloody_owner / bloody_app / keycloak and databases bloody, bloody_test, keycloak initialised"
