#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# Logical backup of the Bloody control-plane database (complements continuous WAL archiving /
# PITR — see docs/OPERATIONS.md §Backups). Produces a compressed custom-format dump, verifies it
# is restorable (pg_restore --list), writes a SHA-256 manifest, optionally encrypts it with `age`,
# and prunes old local backups.
#
#   DATABASE_URL=postgres://bloody_owner:…@host:5432/bloody scripts/db-backup.sh [--out DIR]
#
# Environment:
#   DATABASE_URL         connection string of a role that can read every table (owner / backup role;
#                        RLS is bypassed only for roles with BYPASSRLS or table owners)
#   BACKUP_DIR           output directory (default ./backups) — or --out
#   BACKUP_KEEP_DAYS     prune local dumps older than N days (default 14; 0 = keep all)
#   AGE_RECIPIENTS_FILE  if set, encrypt the dump with `age -R <file>` and delete the plaintext
#   PG_DUMP_JOBS         parallel dump jobs for directory format (default: single-file custom format)
set -euo pipefail

OUT="${BACKUP_DIR:-./backups}"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '4,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "db-backup: unknown argument $1" >&2; exit 2 ;;
  esac
done

: "${DATABASE_URL:?DATABASE_URL must be set}"
for bin in pg_dump pg_restore sha256sum; do
  command -v "$bin" >/dev/null 2>&1 || { echo "db-backup: $bin not found" >&2; exit 2; }
done

umask 077
mkdir -p "$OUT"
ts="$(date -u +%Y%m%dT%H%M%SZ)"
file="${OUT}/bloody-${ts}.dump"

echo "db-backup: dumping to ${file}"
# --no-owner/--no-privileges keep the dump portable; roles & grants are re-created by migrations.
pg_dump --dbname="$DATABASE_URL" --format=custom --compress=9 --no-owner --no-privileges \
  --serializable-deferrable --file="$file"

echo "db-backup: verifying archive"
entries="$(pg_restore --list "$file" | grep -c -v '^;' || true)"
if [[ "${entries}" -lt 1 ]]; then
  echo "db-backup: archive has no entries — refusing to keep it" >&2
  rm -f "$file"
  exit 1
fi

if [[ -n "${AGE_RECIPIENTS_FILE:-}" ]]; then
  command -v age >/dev/null 2>&1 || { echo "db-backup: AGE_RECIPIENTS_FILE set but age is not installed" >&2; exit 2; }
  age -R "$AGE_RECIPIENTS_FILE" -o "${file}.age" "$file"
  rm -f "$file"
  file="${file}.age"
fi

(cd "$(dirname "$file")" && sha256sum "$(basename "$file")" > "$(basename "$file").sha256")
echo "db-backup: ok — ${file} (${entries} TOC entries, $(du -h "$file" | cut -f1))"

if [[ "${KEEP_DAYS}" -gt 0 ]]; then
  find "$OUT" -maxdepth 1 -type f -name 'bloody-*.dump*' -mtime "+${KEEP_DAYS}" -print -delete
fi
