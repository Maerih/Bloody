#!/usr/bin/env bash
# Bloody — restore a backup made by scripts/backup.sh, on this server or a new one.
#
#   bash scripts/restore.sh backups/bloody-<host>-<timestamp>.tar
#   bash scripts/restore.sh <archive> --yes        # no confirmation prompt
#
# 1. checks the archive, 2. takes a safety backup of the current database, 3. stops Bloody,
# 4. replaces the database with the backup, 5. takes the encryption key (and session secret) from
# the backup so stored integration credentials stay readable — this server's address and database
# passwords are kept, 6. applies newer migrations and re-checks row-level security, 7. starts Bloody.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="/usr/local/bin:$PATH"
. scripts/lib.sh

ARCHIVE="" YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) YES=1 ;;
    -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) ARCHIVE="$1" ;;
  esac
  shift
done
[ -n "$ARCHIVE" ] || { echo "usage: bash scripts/restore.sh <backup.tar> [--yes]" >&2; exit 2; }
[ -f "$ARCHIVE" ] || { echo "no such file: $ARCHIVE" >&2; exit 1; }
[ -f .env ] || { echo "no .env — run ./install.sh on this server first, then restore" >&2; exit 1; }
DB_URL="$(bloody_env_get DATABASE_URL)"
if [ "$(id -u)" = 0 ]; then SUDO=""; else SUDO="sudo"; fi

umask 077
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
tar -xf "$ARCHIVE" -C "$work" manifest.json db.dump env 2>/dev/null || { echo "not a Bloody backup (manifest.json, db.dump, env expected)" >&2; exit 1; }
pg_restore --list "$work/db.dump" > /dev/null || { echo "the database dump in this archive is unreadable" >&2; exit 1; }
echo "backup: $(tr -d '\n' < "$work/manifest.json")"

if [ "$YES" != 1 ]; then
  echo
  echo "This REPLACES all Bloody data in database $(echo "$DB_URL" | sed -E 's#.*/##') with the backup."
  read -r -p "Type 'restore' to continue: " answer
  [ "$answer" = restore ] || { echo "cancelled"; exit 1; }
fi

echo "==> Safety backup of the current data"
bash scripts/backup.sh --label pre-restore

echo "==> Stopping Bloody"
was_service=0 was_bg=0
if command -v systemctl >/dev/null && systemctl is-active --quiet bloody 2>/dev/null; then
  $SUDO systemctl stop bloody; was_service=1
elif [ -f logs/bloody.pid ] && kill -0 "$(cat logs/bloody.pid)" 2>/dev/null; then
  kill -TERM -- "-$(cat logs/bloody.pid)" 2>/dev/null || true; was_bg=1
  for _ in $(seq 1 15); do kill -0 "$(cat logs/bloody.pid)" 2>/dev/null || break; sleep 1; done
fi

echo "==> Restoring the database"
psql "$DB_URL" -v ON_ERROR_STOP=1 -q <<'SQL'
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO bloody_app;
SQL
pg_restore --no-owner --exit-on-error --single-transaction --dbname="$DB_URL" "$work/db.dump"

echo "==> Secrets"
# Integration credentials are encrypted with the backup's key: use it (and its retired keys). A
# backup without an explicit key used the built-in development key.
dev_key="$(printf %s 'bloody-dev-only-encryption-key!!' | base64)"
from_backup() { grep -E "^(BLOODY_)?$1=" "$work/env" | tail -1 | cut -d= -f2- || true; }
key="$(from_backup ENCRYPTION_KEY)"; key="${key:-$dev_key}"
changed=()
# Effective value in this server's .env (either spelling; built-in defaults when unset).
current() { local v; v="$(bloody_env_get "$1")"; [ -n "$v" ] || v="$(bloody_env_get "BLOODY_$1")"; echo "${v:-${2:-}}"; }
set_secret() {
  local k="$1" v="$2" default="${3:-}"
  [ "$(current "$k" "$default")" = "${v:-$default}" ] && return 0
  # Drop the alternative spelling so exactly one value is in effect.
  if grep -qE "^BLOODY_$k=" .env; then sed -i -E "/^BLOODY_$k=/d" .env; fi
  bloody_env_set "$k" "$v"; changed+=("$k")
}
set_secret ENCRYPTION_KEY "$key" "$dev_key"
set_secret ENCRYPTION_KEY_VERSION "$(from_backup ENCRYPTION_KEY_VERSION | grep . || echo 1)" 1
set_secret ENCRYPTION_PREVIOUS_KEYS "$(from_backup ENCRYPTION_PREVIOUS_KEYS)"
jwt="$(from_backup JWT_SECRET)"
[ -n "$jwt" ] && set_secret JWT_SECRET "$jwt"
if [ ${#changed[@]} -gt 0 ]; then echo "    taken from the backup: ${changed[*]}"; else echo "    unchanged (same keys)"; fi

echo "==> Applying migrations and re-checking row-level security"
pnpm --silent db:migrate

echo "==> Starting Bloody"
if [ "$was_service" = 1 ]; then
  $SUDO systemctl start bloody
  echo "    started (sudo systemctl status bloody)"
elif [ "$was_bg" = 1 ]; then
  echo "    re-run ./install.sh to start it again in the background"
else
  echo "    Bloody was not running; start it with: sudo systemctl start bloody (or ./install.sh)"
fi
echo "Restore complete. The data before the restore is in the pre-restore backup above."
