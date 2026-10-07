#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# First boot: generate the server configuration (own CA, frontend/GUI/API listeners, datastore
# under the persistent volume), create the administrator, and issue an API client certificate
# for Bloody (role: api + investigator — enough to schedule collections, not to administer the
# server). Later boots reuse the persisted configuration. Then run the frontend in foreground.
set -eu

DATA=/var/lib/velociraptor
CONF="$DATA/server.config.yaml"
API_DIR="$DATA/api-clients"
FRONTEND_HOSTNAME="${VELOCIRAPTOR_FRONTEND_HOSTNAME:-velociraptor}"
GUI_PUBLIC_URL="${VELOCIRAPTOR_GUI_PUBLIC_URL:-https://localhost:8889/}"
ADMIN_USER="${VELOCIRAPTOR_ADMIN_USER:-admin}"
: "${VELOCIRAPTOR_ADMIN_PASSWORD:?VELOCIRAPTOR_ADMIN_PASSWORD must be set}"

umask 077
if [ ! -s "$CONF" ]; then
  echo "velociraptor: generating server configuration"
  velociraptor config generate --merge "{
    \"Frontend\": {\"hostname\": \"$FRONTEND_HOSTNAME\", \"bind_address\": \"0.0.0.0\", \"bind_port\": 8000},
    \"GUI\": {\"bind_address\": \"0.0.0.0\", \"bind_port\": 8889, \"public_url\": \"$GUI_PUBLIC_URL\"},
    \"API\": {\"bind_address\": \"0.0.0.0\", \"bind_port\": 8001},
    \"Datastore\": {\"implementation\": \"FileBaseDataStore\", \"location\": \"$DATA/datastore\", \"filestore_directory\": \"$DATA/filestore\"},
    \"Logging\": {\"output_directory\": \"$DATA/logs\", \"separate_logs_per_component\": true}
  }" > "$CONF.tmp"
  mv "$CONF.tmp" "$CONF"
  velociraptor --config "$CONF" user add --role administrator "$ADMIN_USER" "$VELOCIRAPTOR_ADMIN_PASSWORD"
  mkdir -p "$API_DIR"
  velociraptor --config "$CONF" config api_client --name bloody --role api,investigator "$API_DIR/bloody.api.config.yaml"
  echo "velociraptor: API client config for Bloody written to $API_DIR/bloody.api.config.yaml (store it in the secret store)"
fi

exec velociraptor --config "$CONF" frontend -v
