#!/usr/bin/env bash
# Bloody — backup: database (pg_dump custom format, verified) + .env secrets + manifest, in one
# archive under backups/ (owner-only). Keeps the newest BLOODY_BACKUP_KEEP (default 14).
# Runs daily from the bloody-backup.timer that ./install.sh installs.
#
#   bash scripts/backup.sh                 # → backups/bloody-<host>-<UTC timestamp>.tar
#   bash scripts/backup.sh --label pre-update
#
# The archive contains the ENCRYPTION_KEY (integration credentials can only be decrypted with it):
# keep copies off the server, on encrypted storage. To copy each new archive automatically, set
# BLOODY_BACKUP_HOOK in .env, e.g.  BLOODY_BACKUP_HOOK=rclone copy "$1" remote-crypt:bloody
# (the archive path is passed as $1).
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/usr/local/bin:$PATH"
. scripts/lib.sh

LABEL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --label) LABEL="${2:?--label needs a value}"; shift ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ -z "$LABEL" || "$LABEL" =~ ^[a-z0-9-]{1,40}$ ]] || { echo "--label: lowercase letters, digits and - only" >&2; exit 2; }

[ -f .env ] || { echo "no .env — run ./install.sh first" >&2; exit 1; }
DB_URL="$(bloody_env_get DATABASE_URL)"
[ -n "$DB_URL" ] || { echo "DATABASE_URL missing in .env" >&2; exit 1; }
command -v pg_dump >/dev/null || { echo "pg_dump not found (install the PostgreSQL client)" >&2; exit 1; }

DIR="$(bloody_env_get BLOODY_BACKUP_DIR)"; DIR="${DIR:-backups}"
KEEP="$(bloody_env_get BLOODY_BACKUP_KEEP)"; KEEP="${KEEP:-14}"
umask 077
mkdir -p "$DIR"; chmod 700 "$DIR"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
host="$(hostname -s 2>/dev/null | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9-')"
name="bloody-${host:-server}-${stamp}${LABEL:+-$LABEL}"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

pg_dump --format=custom --compress=6 --no-owner --file="$work/db.dump" "$DB_URL"
# A dump that pg_restore cannot list is not a backup.
pg_restore --list "$work/db.dump" > /dev/null
cp .env "$work/env"
migration="$(psql "$DB_URL" -qAtc "SELECT max(version) FROM schema_migrations" 2>/dev/null || echo unknown)"
cat > "$work/manifest.json" <<JSON
{"format": 1, "createdAt": "$(date -u +%FT%TZ)", "host": "${host}", "label": "${LABEL}",
 "commit": "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)", "migration": "${migration}",
 "postgres": "$(psql "$DB_URL" -qAtc 'SHOW server_version' 2>/dev/null | awk '{print $1}')",
 "dbBytes": $(stat -c %s "$work/db.dump")}
JSON
tar -cf "$DIR/$name.tar.part" -C "$work" manifest.json db.dump env
mv "$DIR/$name.tar.part" "$DIR/$name.tar"
echo "backup: $DIR/$name.tar ($(du -h "$DIR/$name.tar" | cut -f1))"

# Retention: keep the newest $KEEP regular backups (labelled ones count too).
ls -1t "$DIR"/bloody-*.tar 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r old; do rm -f -- "$old"; echo "pruned: $old"; done

hook="$(bloody_env_get BLOODY_BACKUP_HOOK)"
if [ -n "$hook" ]; then
  if bash -c "$hook" bloody-backup-hook "$DIR/$name.tar"; then echo "off-site copy: done"; else echo "off-site copy FAILED (BLOODY_BACKUP_HOOK)" >&2; exit 3; fi
fi
