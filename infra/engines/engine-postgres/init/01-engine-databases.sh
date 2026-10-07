#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# First-boot initialisation of the engine-tier Postgres (separate from Bloody's control-plane
# database: engines never get credentials to Bloody's data). One database + owner per engine.
set -eu
: "${TIMESKETCH_DB_PASSWORD:?}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v ts_pw="$TIMESKETCH_DB_PASSWORD" <<'SQL'
CREATE ROLE timesketch LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'ts_pw';
CREATE DATABASE timesketch OWNER timesketch;
REVOKE ALL ON DATABASE timesketch FROM PUBLIC;
SQL
echo "engine-postgres: database timesketch initialised"
