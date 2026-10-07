#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# Development-only PKI: a throw-away CA plus leaf certificates for local TLS endpoints
# (Mailpit SMTP STARTTLS, optional local HTTPS). Bloody's SMTP transport and engine clients
# never disable certificate verification, so local services need certificates the API trusts:
# the API container gets NODE_EXTRA_CA_CERTS=/certs/ca.crt.
#
#   CERT_DIR=/certs scripts/dev-certs.sh        (run by the `dev-certs` compose service)
#   CERT_DIR=./infra/.dev-certs scripts/dev-certs.sh
#
# Idempotent: existing certificates valid for at least 30 more days are kept.
# NEVER use these certificates outside a developer workstation.
set -eu

CERT_DIR="${CERT_DIR:-/certs}"
DAYS="${DEV_CERT_DAYS:-397}"
LEAVES="${DEV_CERT_LEAVES:-mailpit localhost}"
umask 022
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

valid_for_30_days() {
  [ -s "$1" ] && openssl x509 -checkend 2592000 -noout -in "$1" >/dev/null 2>&1
}

if ! valid_for_30_days ca.crt || [ ! -s ca.key ]; then
  echo "dev-certs: creating development CA"
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days "$DAYS" \
    -keyout ca.key -out ca.crt \
    -subj "/O=Bloody Development/CN=Bloody Dev Root CA (DO NOT TRUST IN PRODUCTION)" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
fi

for name in $LEAVES; do
  if valid_for_30_days "$name.crt" && [ -s "$name.key" ] && openssl verify -CAfile ca.crt "$name.crt" >/dev/null 2>&1; then
    continue
  fi
  echo "dev-certs: issuing certificate for $name"
  cat > "$name.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$name,DNS:localhost,IP:127.0.0.1
EOF
  openssl req -new -newkey rsa:2048 -sha256 -nodes -keyout "$name.key" -out "$name.csr" \
    -subj "/O=Bloody Development/CN=$name" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "$DAYS" -sha256 -extfile "$name.ext" -out "$name.crt" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
done

# Dev-only: services in the compose stack run as different non-root UIDs and must read their key.
chmod 0644 ./*.crt ./*.key
chmod 0600 ca.key
echo "dev-certs: ready in $CERT_DIR ($(ls -1 ./*.crt | tr '\n' ' '))"
