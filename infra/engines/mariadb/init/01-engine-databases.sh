#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# First-boot initialisation of the shared engine MariaDB (GPL-2.0 server, run unmodified as a
# separate service). One database + one least-privilege account per engine; engines never share
# credentials. Runs from /docker-entrypoint-initdb.d.
set -eu
: "${MISP_DB_PASSWORD:?}"
: "${COPILOT_DB_PASSWORD:?}"

mariadb --protocol=socket -uroot -p"${MARIADB_ROOT_PASSWORD}" <<SQL
CREATE DATABASE IF NOT EXISTS misp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS copilot CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'misp'@'%' IDENTIFIED BY '${MISP_DB_PASSWORD}';
CREATE USER IF NOT EXISTS 'copilot'@'%' IDENTIFIED BY '${COPILOT_DB_PASSWORD}';
GRANT ALL PRIVILEGES ON misp.* TO 'misp'@'%';
GRANT ALL PRIVILEGES ON copilot.* TO 'copilot'@'%';
FLUSH PRIVILEGES;
SQL
echo "engine-mariadb: databases misp, copilot initialised"
