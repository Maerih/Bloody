#!/usr/bin/env bash
# Bloody — health check. Verifies every piece a running install needs (LAN or public mode) and
# says how to fix anything that is wrong. Read-only; safe to run any time.
#
#   bash scripts/doctor.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
export PATH="/usr/local/bin:$PATH"
. scripts/lib.sh

if [ -t 1 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; N=$'\e[0m'; else G=""; Y=""; R=""; B=""; N=""; fi
FAILS=0; WARNS=0
ok()   { echo "  ${G}✔${N} $1"; }
warn() { echo "  ${Y}!${N} $1"; [ -n "${2:-}" ] && echo "      fix: $2"; WARNS=$((WARNS + 1)); }
fail() { echo "  ${R}✘${N} $1"; [ -n "${2:-}" ] && echo "      fix: $2"; FAILS=$((FAILS + 1)); }
section() { echo; echo "${B}$1${N}"; }
env_get() { bloody_env_get "$1"; }
http_code() { curl -s --noproxy '*' -o /dev/null -m 8 -w '%{http_code}' "$@" 2>/dev/null; true; }
restart_hint() { if [ -f /etc/systemd/system/bloody.service ]; then echo "sudo systemctl restart bloody"; else echo "./install.sh"; fi; }

MODE="$(env_get BLOODY_MODE)"; MODE="${MODE:-lan}"
DOMAIN="$(env_get BLOODY_DOMAIN)"
PUBLIC="$(env_get PUBLIC_URL)"; PUBLIC="${PUBLIC:-http://localhost:5173}"

section "System"
. /etc/os-release 2>/dev/null && ok "${PRETTY_NAME:-Linux} ($(uname -m))"
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
if [ "$mem_mb" -ge 3500 ]; then ok "memory ${mem_mb} MB"; else warn "memory ${mem_mb} MB (4 GB+ recommended)" "add RAM or swap"; fi
disk_gb=$(df -Pk . | awk 'NR==2 {print int($4/1024/1024)}')
if [ "$disk_gb" -ge 5 ]; then ok "free disk ${disk_gb} GB"; else warn "free disk ${disk_gb} GB (5 GB+ recommended)" "free some space"; fi
ok "mode: ${MODE}$([ "$MODE" = public ] && echo " (HTTPS${DOMAIN:+ for $DOMAIN})")"

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
    if [ "$MODE" = public ]; then fail "no JWT_SECRET on an internet-facing install" "add JWT_SECRET=<64 random chars> to .env, then $(restart_hint)"
    else warn "no JWT_SECRET (using the built-in development secret)" "add JWT_SECRET=<64 random chars> to .env, then restart (everyone is logged out)"; fi
  fi
  [ -n "$(env_get ENCRYPTION_KEY)$(env_get BLOODY_ENCRYPTION_KEY)" ] || warn "no ENCRYPTION_KEY (using the built-in development key)" "only set it on a fresh install: existing stored credentials would become unreadable"
  ok "public URL ${PUBLIC}"
  if [ "$MODE" = public ]; then
    [ "$(env_get COOKIE_SECURE)" = true ] || fail "COOKIE_SECURE is not true on an HTTPS install" "re-run ./install.sh"
    [ "$(env_get BLOODY_WEB_HOST)" = 127.0.0.1 ] || fail "the app listens on every interface; only HTTPS (Caddy) should be exposed" "re-run ./install.sh"
  elif [ "$(env_get BLOODY_ADDRESS_MODE)" = auto ]; then
    cur="http://$(bloody_detect_ip):$(env_get BLOODY_WEB_PORT | grep . || echo 5173)"
    if [ "$PUBLIC" = "$cur" ]; then ok "address follows the server (currently $(bloody_detect_ip))"
    else warn "the server's address changed to ${cur#http://} (the UI still works there; links in e-mails use the old one)" "$(restart_hint)"; fi
  fi
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
    accounts=$(psql "$db_url" -qAtc "SELECT count(*) FROM accounts" 2>/dev/null || echo 0)
    if [ "${accounts:-0}" -gt 0 ]; then ok "$accounts account(s) in the database"; else fail "no accounts yet — nobody can log in" "pnpm admin create-account --name \"My SOC\" --email you@example.com"; fi
    # Logins still on the publicly known demo password (offline hash check — no login attempts).
    weak=$(pnpm --silent admin status 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).demoPasswordUsers.join(" "))}catch{}})')
    if [ -n "$weak" ]; then
      n=$(echo "$weak" | wc -w)
      if [ "$MODE" = public ]; then
        fail "$n login(s) still use the public demo password on an internet-facing install: $weak" "pnpm admin reset-password --email <each address> (or reinstall without demo data)"
      else
        warn "$n demo login(s) use the public demo password (fine for a demo, not for real data)" "pnpm admin reset-password --email <address> before real use"
      fi
    fi
  else
    fail "cannot connect to PostgreSQL with DATABASE_URL" "sudo systemctl start postgresql; re-run ./install.sh"
  fi
fi

section "Running services"
if command -v systemctl >/dev/null && [ -f /etc/systemd/system/bloody.service ]; then
  if systemctl is-active --quiet bloody; then ok "bloody service running (starts on boot: $(systemctl is-enabled bloody 2>/dev/null))"; else fail "bloody service is not running" "sudo systemctl restart bloody; logs: journalctl -u bloody -n 100"; fi
elif [ -f logs/bloody.pid ] && kill -0 "$(cat logs/bloody.pid)" 2>/dev/null; then
  warn "running in the background without systemd (does not survive a reboot)" "after a reboot: ./install.sh"
else
  warn "not installed as a service (stops when you log out)" "./install.sh installs it, or run: bash scripts/start-demo.sh --prod"
fi
api=$(http_code http://127.0.0.1:4000/api/v1/healthz)
if [ "$api" = 200 ]; then ok "API healthy on 127.0.0.1:4000"; else fail "API not answering (HTTP $api)" "$(restart_hint)"; fi
web=$(http_code "http://127.0.0.1:5173/")
if [ "$web" = 200 ]; then ok "web UI running"; else fail "web UI not running on port 5173" "$(restart_hint)"; fi
if [ "$web" = 200 ]; then
  proxy=$(http_code "http://127.0.0.1:5173/api/v1/healthz")
  if [ "$proxy" = 200 ]; then ok "UI → API proxy works"; else fail "UI cannot reach the API (HTTP $proxy)" "$(restart_hint)"; fi
fi

if [ "$MODE" = public ]; then
  section "HTTPS (Caddy)"
  if (command -v systemctl >/dev/null && systemctl is-active --quiet caddy 2>/dev/null) || pgrep -x caddy >/dev/null; then ok "Caddy running"; else fail "Caddy is not running" "sudo systemctl restart caddy; logs: journalctl -u caddy -n 50"; fi
  site="${PUBLIC#https://}"; site="${site%%/*}"
  # An IP certificate is chosen by the address connected to; a domain one by SNI.
  if [[ "$site" =~ ^[0-9.]+$ ]]; then via=(); else via=(--resolve "${site}:443:127.0.0.1"); fi
  insecure=$(http_code -k "${via[@]}" "https://${site}/")
  if [ "$insecure" = 200 ]; then
    ok "HTTPS serves the app on ${site}"
    if [ -n "$DOMAIN" ]; then
      trusted=$(http_code "${via[@]}" "https://${site}/")
      if [ "$trusted" = 200 ]; then ok "trusted certificate for ${DOMAIN}"
      else warn "no trusted certificate for ${DOMAIN} yet" "DNS A record ${DOMAIN} → this server, ports 80+443 open (also in the cloud firewall); then: journalctl -u caddy -n 50"; fi
    else
      warn "self-signed certificate (browsers warn)" "re-run with --domain <name> for a trusted certificate"
    fi
  elif [ -n "$DOMAIN" ] && [ "$(http_code --resolve "${site}:80:127.0.0.1" "http://${site}/")" = 308 ]; then
    # Caddy serves the site (HTTP → HTTPS redirect) but has no certificate yet.
    resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1 {print $1}' || true)"
    if [ -z "$resolved" ]; then
      warn "no certificate yet: ${DOMAIN} does not resolve" "create a DNS A record ${DOMAIN} → this server's public IP; Caddy retries automatically"
    else
      warn "no certificate yet for ${DOMAIN} (resolves to ${resolved})" "make sure ${resolved} is this server and ports 80+443 are open (also in the cloud firewall); journalctl -u caddy -n 50"
    fi
  else
    fail "HTTPS on ${site} does not serve the app (HTTP $insecure)" "sudo caddy validate --config /etc/caddy/Caddyfile; journalctl -u caddy -n 50"
  fi
  if command -v ss >/dev/null && ss -ltn | grep -qE '(0\.0\.0\.0|\*|\[::\]):5173\s'; then
    fail "port 5173 is open on every interface (bypasses HTTPS)" "re-run ./install.sh, then $(restart_hint)"
  fi
else
  section "LAN access"
  if [ "$web" = 200 ]; then
    if [ "$(http_code "$PUBLIC/")" = 200 ]; then ok "reachable at $PUBLIC"; else fail "not reachable at $PUBLIC" "$(restart_hint) (picks up the current address)"; fi
  fi
  host_short="$(hostname -s 2>/dev/null | tr 'A-Z' 'a-z')"
  if pgrep -x avahi-daemon >/dev/null; then ok "mDNS name http://${host_short}.local:5173 (stays valid when the IP changes)"
  else warn "mDNS not running — users need the IP address" "re-run ./install.sh (installs avahi-daemon)"; fi
fi

section "Backups"
bdir="$(env_get BLOODY_BACKUP_DIR)"; bdir="${bdir:-backups}"
latest="$(ls -1t "$bdir"/bloody-*.tar 2>/dev/null | head -1)"
if [ -z "$latest" ]; then
  warn "no backups yet" "bash scripts/backup.sh (./install.sh schedules a daily one)"
else
  age_h=$(( ($(date +%s) - $(stat -c %Y "$latest")) / 3600 ))
  if [ "$age_h" -le 36 ]; then ok "latest backup ${age_h}h old: $latest ($(ls -1 "$bdir"/bloody-*.tar | wc -l) kept)"
  else warn "latest backup is ${age_h}h old: $latest" "bash scripts/backup.sh; check: systemctl status bloody-backup.timer"; fi
  [ -n "$(env_get BLOODY_BACKUP_HOOK)" ] || warn "backups are only on this server" "set BLOODY_BACKUP_HOOK in .env to copy each one off-server (see scripts/backup.sh)"
fi

section "Firewall"
if [ "$MODE" = public ]; then want=(80 443); else want=(5173); fi
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  for p in "${want[@]}"; do ufw status | grep -qE "^${p}(/tcp)?\s+ALLOW" && ok "ufw allows ${p}" || warn "ufw may block port ${p}" "sudo ufw allow ${p}/tcp"; done
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  for p in "${want[@]}"; do firewall-cmd --list-ports | grep -q "${p}/tcp" && ok "firewalld allows ${p}" || warn "firewalld may block port ${p}" "sudo firewall-cmd --permanent --add-port=${p}/tcp && sudo firewall-cmd --reload"; done
else
  ok "no host firewall blocking ports ${want[*]}"
fi
[ "$MODE" = public ] && echo "    (cloud providers also need ports ${want[*]} open in their own firewall / security group)"

if [ "$(env_get BLOODY_EVENT_SEARCH)" = opensearch ]; then
  section "Event search"
  os=$(http_code "$(env_get OPENSEARCH_URL)")
  if [ "$os" = 200 ] || [ "$os" = 401 ]; then ok "OpenSearch reachable"; else warn "OpenSearch not reachable (search falls back to Postgres)" "check OPENSEARCH_URL"; fi
fi

echo
if [ "$FAILS" -gt 0 ]; then echo "${R}${B}$FAILS problem(s)${N}, $WARNS warning(s)."; exit 1; fi
echo "${G}${B}All good${N} ($WARNS warning(s)). Open ${PUBLIC} in a browser."
