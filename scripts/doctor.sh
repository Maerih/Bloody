#!/usr/bin/env bash
# Bloody — health check. Verifies every piece a running install needs and says how to fix
# anything that is wrong. Safe to run any time (read-only).
#
#   bash scripts/doctor.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="/usr/local/bin:$PATH"

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; N=$'\e[0m'; else G=""; Y=""; R=""; B=""; N=""; fi
FAILS=0; WARNS=0
ok()   { echo "  ${G}✔${N} $1"; }
warn() { echo "  ${Y}!${N} $1"; [ -n "${2:-}" ] && echo "      fix: $2"; WARNS=$((WARNS + 1)); }
fail() { echo "  ${R}✘${N} $1"; [ -n "${2:-}" ] && echo "      fix: $2"; FAILS=$((FAILS + 1)); }
section() { echo; echo "${B}$1${N}"; }
env_get() { if [ -f .env ]; then grep -E "^$1=" .env | tail -1 | cut -d= -f2- || true; fi; }
http_code() { curl -s --noproxy '*' -o /dev/null -m 5 -w '%{http_code}' "$1" 2>/dev/null; true; }

section "System"
. /etc/os-release 2>/dev/null && ok "${PRETTY_NAME:-Linux} ($(uname -m))"
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
if [ "$mem_mb" -ge 3500 ]; then ok "memory ${mem_mb} MB"; else warn "memory ${mem_mb} MB (4 GB+ recommended)" "add RAM or swap"; fi
disk_gb=$(df -Pk . | awk 'NR==2 {print int($4/1024/1024)}')
if [ "$disk_gb" -ge 5 ]; then ok "free disk ${disk_gb} GB"; else warn "free disk ${disk_gb} GB (5 GB+ recommended)" "free some space"; fi

section "Software"
node_v=$(node -v 2>/dev/null || true)
node_major=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
if [ "$node_major" -ge 22 ]; then ok "Node.js $node_v"; else fail "Node.js ${node_v:-missing} (22+ required)" "run ./install.sh"; fi
if command -v pnpm >/dev/null; then ok "pnpm $(pnpm -v 2>/dev/null)"; else fail "pnpm missing" "run ./install.sh (or: corepack enable)"; fi
if command -v psql >/dev/null; then ok "PostgreSQL client $(psql --version | awk '{print $3}')"; else fail "PostgreSQL missing" "run ./install.sh"; fi
if [ -f node_modules/.modules.yaml ]; then ok "dependencies installed"; else fail "dependencies not installed" "pnpm install"; fi

section "Configuration (.env)"
if [ ! -f .env ]; then
  fail ".env missing" "run ./install.sh"
else
  ok ".env present"
  perms=$(stat -c %a .env)
  [ "$perms" = 600 ] || warn ".env is readable by other users (mode $perms)" "chmod 600 .env"
  for k in DATABASE_URL BLOODY_APP_DB_PASSWORD PUBLIC_URL; do
    [ -n "$(env_get "$k")" ] || fail "$k not set in .env" "re-run ./install.sh"
  done
  if [ -z "$(env_get JWT_SECRET)$(env_get BLOODY_JWT_SECRET)" ]; then
    warn "no JWT_SECRET (using the built-in development secret)" "add JWT_SECRET=<64 random chars> to .env, then restart (everyone is logged out)"
  fi
  [ -n "$(env_get ENCRYPTION_KEY)$(env_get BLOODY_ENCRYPTION_KEY)" ] || warn "no ENCRYPTION_KEY (using the built-in development key)" "only set it on a fresh install: existing stored credentials would become unreadable"
  ok "public URL $(env_get PUBLIC_URL)"
  url_host=$(env_get PUBLIC_URL | sed -E 's#^[a-z]+://([^:/]+).*#\1#')
  case "$url_host" in
    localhost|127.*) ;;
    *[a-zA-Z]*) ;;  # a DNS name: not checked against local addresses
    *) if ! hostname -I 2>/dev/null | tr ' ' '\n' | grep -qx "$url_host"; then
         warn "PUBLIC_URL points to $url_host, but this server's address is now $(hostname -I | awk '{print $1}')" "re-run ./install.sh (it updates the address), or give the server a fixed IP in your router"
       fi ;;
  esac
fi

section "Database"
db_url=$(env_get DATABASE_URL)
if [ -n "$db_url" ] && command -v psql >/dev/null; then
  if psql "$db_url" -qAtc "SELECT 1" >/dev/null 2>&1; then
    ok "PostgreSQL reachable as bloody_owner ($(psql "$db_url" -qAtc 'SHOW server_version' 2>/dev/null))"
    app_url=$(echo "$db_url" | sed -E "s#//bloody_owner:[^@]*@#//bloody_app:$(env_get BLOODY_APP_DB_PASSWORD)@#")
    if psql "$app_url" -qAtc "SELECT 1" >/dev/null 2>&1; then ok "runtime role bloody_app can log in"; else fail "bloody_app cannot log in" "re-run ./install.sh (resets the role password from .env)"; fi
    pending=$(pnpm --silent --filter @bloody/api exec tsx src/db/migrate.ts --status 2>/dev/null | grep -vc "^applied" || true)
    if [ "${pending:-0}" = 0 ]; then ok "database migrations up to date"; else warn "$pending migration(s) pending" "pnpm db:migrate (or restart: the start script migrates)"; fi
    tenants=$(psql "$db_url" -qAtc "SELECT count(*) FROM accounts" 2>/dev/null || echo 0)
    if [ "${tenants:-0}" -gt 0 ]; then ok "$tenants account(s) in the database"; else warn "no accounts yet" "pnpm db:seed (demo data) or create one"; fi
  else
    fail "cannot connect to PostgreSQL with DATABASE_URL" "sudo systemctl start postgresql; re-run ./install.sh"
  fi
fi

section "Running services"
if command -v systemctl >/dev/null && [ -f /etc/systemd/system/bloody.service ]; then
  if systemctl is-active --quiet bloody; then ok "bloody service running (starts on boot: $(systemctl is-enabled bloody 2>/dev/null))"; else fail "bloody service is not running" "sudo systemctl restart bloody; logs: journalctl -u bloody -n 100"; fi
else
  warn "not installed as a service (stops when you log out)" "./install.sh installs it, or run: bash scripts/start-demo.sh --prod"
fi
api=$(http_code http://127.0.0.1:4000/api/v1/healthz)
if [ "$api" = 200 ]; then ok "API healthy on 127.0.0.1:4000"; else fail "API not answering (HTTP $api)" "sudo systemctl restart bloody (or bash scripts/start-demo.sh --prod)"; fi
public=$(env_get PUBLIC_URL); public=${public:-http://localhost:5173}
web=$(http_code "http://127.0.0.1:5173/")
if [ "$web" = 200 ]; then ok "web UI running on port 5173"; else fail "web UI not running on port 5173" "sudo systemctl restart bloody (or bash scripts/start-demo.sh --prod)"; fi
if [ "$web" = 200 ]; then
  if [ "$(http_code "$public/")" = 200 ]; then ok "reachable at $public"; else fail "not reachable at $public" "check PUBLIC_URL in .env matches this server's address"; fi
  proxy=$(http_code "http://127.0.0.1:5173/api/v1/healthz")
  if [ "$proxy" = 200 ]; then ok "UI → API proxy works"; else fail "UI cannot reach the API (HTTP $proxy)" "sudo systemctl restart bloody"; fi
fi

if [ "$(env_get BLOODY_EVENT_SEARCH)" = opensearch ]; then
  os=$(http_code "$(env_get OPENSEARCH_URL)")
  if [ "$os" = 200 ] || [ "$os" = 401 ]; then ok "OpenSearch reachable"; else warn "OpenSearch not reachable (search falls back to Postgres)" "check OPENSEARCH_URL"; fi
fi

section "Network"
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  if ufw status | grep -qE "^5173(/tcp)?\s+ALLOW"; then ok "firewall (ufw) allows port 5173"; else warn "firewall (ufw) may block port 5173" "sudo ufw allow 5173/tcp"; fi
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  if firewall-cmd --list-ports | grep -q 5173/tcp; then ok "firewall (firewalld) allows port 5173"; else warn "firewall (firewalld) may block port 5173" "sudo firewall-cmd --permanent --add-port=5173/tcp && sudo firewall-cmd --reload"; fi
else
  ok "no host firewall blocking port 5173"
fi

echo
if [ "$FAILS" -gt 0 ]; then echo "${R}${B}$FAILS problem(s)${N}, $WARNS warning(s)."; exit 1; fi
echo "${G}${B}All good${N} ($WARNS warning(s)). Open ${public} in a browser."
