#!/usr/bin/env bash
# Bloody — one-command install on any Linux server (Ubuntu/Debian, Fedora/RHEL/Rocky/Alma):
# a home or office server, a customer's on-prem box, or an internet VPS.
#
#   git clone <repo> bloody && cd bloody && git switch maerih/bloody
#   ./install.sh                                   # auto: LAN mode on a private network, public mode on a VPS
#   ./install.sh --domain soc.example.com          # VPS with a domain: HTTPS with a free Let's Encrypt certificate
#
# Modes
#   LAN     http://<server-ip>:5173 and http://<hostname>.local:5173. Follows the server's IP when it
#           changes (DHCP). Demo data by default.
#   public  HTTPS on 443 through Caddy (Let's Encrypt with --domain, otherwise an encrypted
#           self-signed certificate on the IP). The app itself listens on localhost only. Production
#           settings, no demo data, and a first administrator with a random password.
#
# It checks everything and installs what is missing (Node.js 22, pnpm, PostgreSQL, Caddy/mDNS), sets up
# the database and a private .env, installs the `bloody` service (starts on boot), opens the
# firewall and finishes with a health check. Safe to re-run after `git pull` or any change.
#
# Options
#   --domain <name>        public mode with HTTPS for this domain (its DNS A record → this server)
#   --email <addr>         contact for Let's Encrypt expiry notices (with --domain)
#   --public | --lan       force the mode (default: detected from the server's address)
#   --ip <addr>            fixed address instead of following the server's current IP
#   --admin-email <addr>   first administrator (default: admin@<domain or hostname>)
#   --org-name <name>      name of the account (default: "Security Operations")
#   --enterprise           a single company's own SOC instead of an MSSP serving customers
#   --demo-data | --no-demo-data
#   --no-service           do not install the systemd service
#   -h, --help
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(pwd)"
export PATH="/usr/local/bin:$PATH"
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0 CI=true
. scripts/lib.sh

MDNS=0 MODE="" DOMAIN="" ACME_EMAIL="" FIXED_IP="" SERVICE=1 SEED="" ADMIN_EMAIL="" ORG_NAME="Security Operations" KIND=mssp
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:?--domain needs a name}"; shift ;;
    --domain=*) DOMAIN="${1#*=}" ;;
    --email) ACME_EMAIL="${2:?--email needs an address}"; shift ;;
    --email=*) ACME_EMAIL="${1#*=}" ;;
    --public) MODE=public ;;
    --lan) MODE=lan ;;
    --ip) FIXED_IP="${2:?--ip needs an address}"; shift ;;
    --ip=*) FIXED_IP="${1#*=}" ;;
    --admin-email) ADMIN_EMAIL="${2:?--admin-email needs an address}"; shift ;;
    --admin-email=*) ADMIN_EMAIL="${1#*=}" ;;
    --org-name) ORG_NAME="${2:?--org-name needs a name}"; shift ;;
    --org-name=*) ORG_NAME="${1#*=}" ;;
    --enterprise) KIND=enterprise ;;
    --demo-data) SEED=1 ;;
    --no-demo-data) SEED=0 ;;
    --no-service) SERVICE=0 ;;
    -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

if [ -t 1 ]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'; else B=""; G=""; Y=""; R=""; N=""; fi
step() { echo; echo "${B}==> $*${N}"; }
note() { echo "    $*"; }
die() { echo "${R}error:${N} $*" >&2; exit 1; }

[ -z "$DOMAIN" ] || [[ "$DOMAIN" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]] || die "--domain: \"$DOMAIN\" is not a domain name"
[ -z "$FIXED_IP" ] || [[ "$FIXED_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "--ip: \"$FIXED_IP\" is not an IPv4 address"

if [ "$(id -u)" = 0 ]; then SUDO=""; else
  command -v sudo >/dev/null || die "run as root or install sudo"
  SUDO="sudo"; $SUDO -v || die "sudo access is required to install system packages"
fi
RUN_USER="$(stat -c %U "$REPO")"
as_owner() { if [ "$(id -un)" = "$RUN_USER" ]; then "$@"; else $SUDO -u "$RUN_USER" -H env PATH="$PATH" COREPACK_ENABLE_DOWNLOAD_PROMPT=0 CI=true "$@"; fi; }
has_systemd=0; command -v systemctl >/dev/null && [ -d /run/systemd/system ] && has_systemd=1
svc_enable() { if [ "$has_systemd" = 1 ]; then $SUDO systemctl enable --now "$1" >/dev/null 2>&1; else $SUDO service "$1" start >/dev/null 2>&1; fi; }

# ─── 1. System, address and mode ─────────────────────────────────────────────
step "Checking the system"
[ "$(uname -s)" = Linux ] || die "Linux is required"
. /etc/os-release 2>/dev/null || true
note "${PRETTY_NAME:-Linux} ($(uname -m)), user $RUN_USER"
if command -v apt-get >/dev/null; then PM=apt
elif command -v dnf >/dev/null; then PM=dnf
elif command -v yum >/dev/null; then PM=yum
else die "unsupported distribution (needs apt, dnf or yum). Install Node.js 22, pnpm and PostgreSQL 14+ manually, then run: bash scripts/setup-local.sh"; fi
apt_updated=0
pkg_install() {
  case "$PM" in
    apt) [ "$apt_updated" = 1 ] || { $SUDO apt-get update -q >/dev/null; apt_updated=1; }; $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/dev/null ;;
    *) $SUDO "$PM" install -y -q "$@" >/dev/null ;;
  esac
}
missing=()
for tool in curl git xz tar ip; do command -v "$tool" >/dev/null || missing+=("$tool"); done
if [ ${#missing[@]} -gt 0 ]; then
  note "installing: ${missing[*]}"
  pkgs=(ca-certificates)
  for t in "${missing[@]}"; do
    case "$t" in
      xz) [ "$PM" = apt ] && pkgs+=(xz-utils) || pkgs+=(xz) ;;
      ip) [ "$PM" = apt ] && pkgs+=(iproute2) || pkgs+=(iproute) ;;
      *) pkgs+=("$t") ;;
    esac
  done
  pkg_install "${pkgs[@]}"
fi

DETECTED_IP="$(bloody_detect_ip)"
ADDRESS="${FIXED_IP:-$DETECTED_IP}"
if [ -z "$MODE" ]; then
  if [ -n "$DOMAIN" ]; then MODE=public
  elif [ -f .env ] && [ -n "$(bloody_env_get BLOODY_MODE)" ]; then MODE="$(bloody_env_get BLOODY_MODE)"   # keep the mode of an existing install
  elif bloody_is_private_ip "$ADDRESS"; then MODE=lan
  else MODE=public; fi
fi
[ "$MODE" = public ] && [ -z "$DOMAIN" ] && DOMAIN="$(bloody_env_get BLOODY_DOMAIN)"
if [ "$MODE" = lan ] && bloody_is_cloud_vm; then
  echo "    ${Y}!${N} this looks like a cloud VM with a private address (${ADDRESS}). If it is an internet VPS, re-run with"
  echo "      --domain <name> (recommended) or --public, so it is served over HTTPS instead of plain HTTP."
fi
HOST_SHORT="$(hostname -s 2>/dev/null || hostname)"
[ -n "$SEED" ] || { if [ "$MODE" = lan ]; then SEED=1; else SEED=0; fi; }
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@${DOMAIN:-${HOST_SHORT,,}.local}}"
if [ "$MODE" = public ]; then
  note "mode: public — HTTPS at $([ -n "$DOMAIN" ] && echo "https://$DOMAIN (Let's Encrypt)" || echo "https://$ADDRESS (self-signed)")"
else
  note "mode: LAN — http://${ADDRESS}:5173 $([ -z "$FIXED_IP" ] && echo "(follows IP changes)")"
fi

# ─── 2. Node.js 22 ───────────────────────────────────────────────────────────
step "Node.js"
node_major() { node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0; }
if [ "$(node_major)" -ge 22 ]; then
  note "Node.js $(node -v) ✔"
else
  note "found $(node -v 2>/dev/null || echo 'no Node.js'); installing the official Node.js 22 build into /usr/local"
  case "$(uname -m)" in x86_64) arch=x64 ;; aarch64|arm64) arch=arm64 ;; *) die "unsupported CPU $(uname -m)" ;; esac
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  curl -fsSL https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt -o "$tmp/SHASUMS256.txt" || die "cannot reach nodejs.org"
  file="$(grep -oE "node-v22\.[0-9]+\.[0-9]+-linux-${arch}\.tar\.xz" "$tmp/SHASUMS256.txt" | head -1)"
  [ -n "$file" ] || die "no Node.js 22 build for linux-$arch"
  curl -fsSL "https://nodejs.org/dist/latest-v22.x/$file" -o "$tmp/$file"
  (cd "$tmp" && grep " $file\$" SHASUMS256.txt | sha256sum -c --quiet -) || die "Node.js download failed its checksum"
  $SUDO tar -xJf "$tmp/$file" -C /usr/local --strip-components=1 --no-same-owner
  hash -r
  [ "$(node_major)" -ge 22 ] || die "Node.js 22 installed in /usr/local/bin but an older node comes first in PATH ($(command -v node))"
  note "Node.js $(node -v) ✔"
fi

# ─── 3. pnpm (version pinned by package.json) ────────────────────────────────
step "pnpm"
want_pnpm="$(node -p 'require("./package.json").packageManager.split("@")[1]')"
if [ "$(pnpm -v 2>/dev/null || true)" != "$want_pnpm" ]; then
  note "activating pnpm $want_pnpm via corepack"
  $SUDO env PATH="$PATH" COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack enable --install-directory "$(dirname "$(command -v node)")" ||
    $SUDO env PATH="$PATH" npm install -g --silent "pnpm@$want_pnpm"
  as_owner corepack prepare "pnpm@$want_pnpm" --activate >/dev/null 2>&1 || true
  hash -r
fi
command -v pnpm >/dev/null || die "pnpm could not be installed"
note "pnpm $(as_owner pnpm -v) ✔"

# ─── 4. PostgreSQL ───────────────────────────────────────────────────────────
step "PostgreSQL"
if ! command -v psql >/dev/null || ! { [ -d /etc/postgresql ] || [ -d /var/lib/pgsql ] || command -v pg_ctl >/dev/null || ls /usr/lib/postgresql/*/bin/postgres >/dev/null 2>&1; }; then
  note "installing PostgreSQL"
  if [ "$PM" = apt ]; then
    pkg_install postgresql postgresql-contrib
  else
    pkg_install postgresql-server postgresql-contrib
    [ -f /var/lib/pgsql/data/PG_VERSION ] || $SUDO postgresql-setup --initdb >/dev/null
    # Allow password logins over localhost TCP (Fedora/RHEL default is ident).
    $SUDO sed -i -E 's#^(host\s+all\s+all\s+(127\.0\.0\.1/32|::1/128)\s+)ident#\1scram-sha-256#' /var/lib/pgsql/data/pg_hba.conf
  fi
fi
svc_enable postgresql || true
note "$(psql --version) ✔"

# ─── 5. Database, .env, dependencies, migrations, demo data ──────────────────
step "Setting up Bloody (database, .env, dependencies, migrations$([ "$SEED" = 1 ] && echo ', demo data'))"
setup_env=(BLOODY_SEED="$SEED")
[ -n "$FIXED_IP" ] && setup_env+=(BLOODY_IP="$FIXED_IP")
# Demo data needs NODE_ENV=development; set the mode first so a re-run keeps a public install in production.
as_owner env "${setup_env[@]}" bash scripts/setup-local.sh

# Mode-specific settings (re-applied on every run, so switching modes works).
if [ "$MODE" = public ]; then
  url="https://${DOMAIN:-$ADDRESS}"
  bloody_env_set BLOODY_MODE public
  bloody_env_set BLOODY_DOMAIN "$DOMAIN"
  bloody_env_set BLOODY_ADDRESS_MODE fixed
  bloody_env_set PUBLIC_URL "$url"
  bloody_env_set CORS_ORIGINS "$url"
  bloody_env_set BLOODY_WEB_HOST 127.0.0.1        # only Caddy (HTTPS) is exposed
  bloody_env_set BLOODY_WEB_ALLOWED_HOSTS "${DOMAIN}"
  bloody_env_set COOKIE_SECURE true
  bloody_env_set TRUST_PROXY true
  bloody_env_set BLOODY_AI_ALLOW_PRIVATE_ENDPOINTS false
  if [ "$SEED" = 1 ]; then bloody_env_set NODE_ENV development; else bloody_env_set NODE_ENV production; fi
else
  bloody_env_set BLOODY_MODE lan
  bloody_env_set BLOODY_DOMAIN ""
  if [ -n "$FIXED_IP" ]; then
    bloody_env_set BLOODY_ADDRESS_MODE fixed
    bloody_env_set PUBLIC_URL "http://${FIXED_IP}:5173"
    bloody_env_set CORS_ORIGINS "http://${FIXED_IP}:5173,http://localhost:5173"
  else
    bloody_env_set BLOODY_ADDRESS_MODE auto
    bloody_refresh_address || true
  fi
  bloody_env_set BLOODY_WEB_HOST 0.0.0.0
  bloody_env_set BLOODY_WEB_ALLOWED_HOSTS "${HOST_SHORT,,}.local,${HOST_SHORT,,}"
  bloody_env_set COOKIE_SECURE false
  bloody_env_set TRUST_PROXY false
  bloody_env_set NODE_ENV development
fi
chown "$RUN_USER" .env 2>/dev/null || $SUDO chown "$RUN_USER" .env
chmod 600 .env

# First administrator for real (non-demo) installs: random password, shown once.
ADMIN_PASSWORD=""
if [ "$SEED" = 0 ]; then
  out="$(as_owner pnpm --silent admin create-account --name "$ORG_NAME" --email "$ADMIN_EMAIL" --kind "$KIND")" || die "could not create the administrator: $out"
  ADMIN_PASSWORD="$(echo "$out" | sed -nE 's/^ *password: (.*)$/\1/p')"
  # Print it right away too, so it is not lost if a later step fails.
  echo "$out" | sed 's/^/    /'
fi
if [ "$MODE" = public ] && as_owner pnpm --silent admin status 2>/dev/null | grep -q '"demo":true'; then
  echo "    ${Y}!${N} the demo login admin@bloody.local (public password) exists on this internet-facing server."
  echo "      Remove the demo data (fresh database) or at least change that password immediately."
fi

# ─── 6. Reverse proxy (public) / mDNS name (LAN) ─────────────────────────────
if [ "$MODE" = public ]; then
  step "HTTPS (Caddy)"
  command -v caddy >/dev/null || { note "installing Caddy"; pkg_install caddy || die "could not install Caddy (Fedora/RHEL: enable EPEL or COPR @caddy/caddy, then re-run)"; }
  $SUDO mkdir -p /etc/caddy
  site="${DOMAIN:-$ADDRESS}"
  tls_line="tls internal"
  if [ -n "$DOMAIN" ]; then
    if [ -n "$ACME_EMAIL" ]; then tls_line="tls ${ACME_EMAIL}"; else tls_line="# automatic HTTPS: Let's Encrypt / ZeroSSL"; fi
  fi
  $SUDO tee /etc/caddy/bloody.caddy >/dev/null <<CADDY
# Managed by Bloody install.sh — HTTPS front end for the Command Center.
${site} {
	${tls_line}
	encode zstd gzip
	reverse_proxy 127.0.0.1:5173
}
CADDY
  if [ ! -f /etc/caddy/Caddyfile ] || grep -q "/usr/share/caddy" /etc/caddy/Caddyfile; then
    # Stock welcome page (or none): Bloody owns this Caddy.
    printf '# Managed by Bloody install.sh\nimport /etc/caddy/bloody.caddy\n' | $SUDO tee /etc/caddy/Caddyfile >/dev/null
  elif ! grep -q "import /etc/caddy/bloody.caddy" /etc/caddy/Caddyfile; then
    echo "import /etc/caddy/bloody.caddy" | $SUDO tee -a /etc/caddy/Caddyfile >/dev/null
    note "added an import to your existing /etc/caddy/Caddyfile"
  fi
  $SUDO caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 || die "Caddy configuration is invalid: sudo caddy validate --config /etc/caddy/Caddyfile"
  if [ "$has_systemd" = 1 ]; then
    $SUDO systemctl enable caddy >/dev/null 2>&1; $SUDO systemctl reload-or-restart caddy
  else
    $SUDO caddy stop >/dev/null 2>&1 || true
    (cd /etc/caddy && $SUDO caddy start --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1) || die "Caddy failed to start"
  fi
  note "Caddy ✔ ($( [ -n "$DOMAIN" ] && echo "certificate for $DOMAIN is requested automatically" || echo "self-signed certificate for $ADDRESS"))"
  if [ -n "$DOMAIN" ]; then
    resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1 {print $1}' || true)"
    if [ -z "$resolved" ]; then
      echo "    ${Y}!${N} $DOMAIN does not resolve yet. Create a DNS A record: $DOMAIN → this server's public IP."
    elif ! bloody_is_private_ip "$DETECTED_IP" && [ "$resolved" != "$DETECTED_IP" ]; then
      echo "    ${Y}!${N} $DOMAIN points to $resolved but this server is $DETECTED_IP — fix the DNS A record."
    fi
  fi
else
  step "Network name (mDNS)"
  if [ ! -x /usr/sbin/avahi-daemon ]; then
    if [ "$PM" = apt ]; then pkg_install avahi-daemon libnss-mdns || true; else pkg_install avahi nss-mdns || true; fi
  fi
  if [ -x /usr/sbin/avahi-daemon ]; then
    svc_enable avahi-daemon || true
    sleep 1
  fi
  if pgrep -x avahi-daemon >/dev/null; then
    MDNS=1
    note "also reachable as http://${HOST_SHORT,,}.local:5173 (stays valid when the IP changes)"
  else
    note "mDNS could not be started here — use the IP address"
  fi
fi

# ─── 7. Service ──────────────────────────────────────────────────────────────
wait_up() {
  for _ in $(seq 1 180); do
    curl -fsS --noproxy '*' -o /dev/null http://127.0.0.1:5173/ 2>/dev/null && curl -fsS --noproxy '*' -o /dev/null http://127.0.0.1:4000/api/v1/healthz 2>/dev/null && return 0
    "$@" || return 1
    sleep 2
  done
}
if [ "$SERVICE" = 1 ] && [ "$has_systemd" = 1 ]; then
  step "Installing the bloody service (starts on boot)"
  if ! systemctl is-active --quiet bloody 2>/dev/null && command -v ss >/dev/null && ss -ltn | grep -qE ':(4000|5173)\s'; then
    die "ports 4000/5173 are already in use — stop the running start-demo.sh (Ctrl+C) and re-run ./install.sh"
  fi
  $SUDO tee /etc/systemd/system/bloody.service >/dev/null <<UNIT
[Unit]
Description=Bloody Security Command Center
After=network-online.target postgresql.service
Wants=network-online.target postgresql.service

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${REPO}
Environment=PATH=/usr/local/bin:/usr/bin:/bin
Environment=COREPACK_ENABLE_DOWNLOAD_PROMPT=0
Environment=CI=true
ExecStart=/bin/bash ${REPO}/scripts/start-demo.sh --prod
Restart=on-failure
RestartSec=5
TimeoutStartSec=300
KillMode=control-group

[Install]
WantedBy=multi-user.target
UNIT
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable bloody >/dev/null 2>&1
  $SUDO systemctl restart bloody
  note "building the UI and starting (first start takes a minute) ..."
  wait_up bash -c '! systemctl is-failed --quiet bloody' || true
elif [ "$SERVICE" = 1 ]; then
  # No systemd (container, WSL …): start in the background now; it will not survive a reboot.
  step "Starting Bloody in the background (no systemd: re-run ./install.sh after a reboot)"
  mkdir -p logs && chown "$RUN_USER" logs 2>/dev/null || true
  if [ -f logs/bloody.pid ] && kill -0 "$(cat logs/bloody.pid)" 2>/dev/null; then
    note "stopping the previous run"
    kill -TERM -- "-$(cat logs/bloody.pid)" 2>/dev/null || true
    for _ in $(seq 1 15); do kill -0 "$(cat logs/bloody.pid)" 2>/dev/null || break; sleep 1; done
  fi
  rm -f logs/bloody.pid
  as_owner env BLOODY_PIDFILE="$REPO/logs/bloody.pid" setsid nohup bash scripts/start-demo.sh --prod > logs/bloody.log 2>&1 < /dev/null &
  for _ in $(seq 1 10); do [ -s logs/bloody.pid ] && break; sleep 0.5; done
  note "building the UI and starting (first start takes a minute) ..."
  wait_up bash -c "kill -0 \$(cat '$REPO/logs/bloody.pid')" || true
fi

# ─── 8. Firewall ─────────────────────────────────────────────────────────────
if [ "$MODE" = public ]; then ports=(80/tcp 443/tcp); else ports=(5173/tcp); fi
if command -v ufw >/dev/null && $SUDO ufw status 2>/dev/null | grep -q "Status: active"; then
  step "Firewall (ufw): allowing ${ports[*]}"
  for p in "${ports[@]}"; do $SUDO ufw allow "$p" >/dev/null; done
elif command -v firewall-cmd >/dev/null && $SUDO firewall-cmd --state >/dev/null 2>&1; then
  step "Firewall (firewalld): allowing ${ports[*]}"
  for p in "${ports[@]}"; do $SUDO firewall-cmd --permanent --add-port="$p" >/dev/null; done
  $SUDO firewall-cmd --reload >/dev/null
fi

# ─── 9. Health check ─────────────────────────────────────────────────────────
step "Health check"
doctor_ok=1
as_owner bash scripts/doctor.sh || doctor_ok=0

URL="$(bloody_env_get PUBLIC_URL)"
echo
if [ "$doctor_ok" = 1 ]; then echo "${G}${B}Bloody is installed.${N}"; else echo "${R}${B}Installed, but the health check found problems (see above).${N}"; fi
echo
echo "  Open:     ${URL}"
[ "$MODE" = lan ] && [ "${MDNS:-0}" = 1 ] && echo "            http://${HOST_SHORT,,}.local:5173   (works even when the IP changes)"
if [ "$SEED" = 1 ]; then
  echo "  Login:    admin@bloody.local / ChangeMe!123   (demo data — change it after the first login)"
elif [ -n "$ADMIN_PASSWORD" ]; then
  echo "  Login:    ${ADMIN_EMAIL} / ${B}${ADMIN_PASSWORD}${N}"
  echo "            (shown once — store it in your password manager; reset: pnpm admin reset-password --email ${ADMIN_EMAIL})"
else
  echo "  Login:    ${ADMIN_EMAIL} (existing password; reset: pnpm admin reset-password --email ${ADMIN_EMAIL})"
fi
[ "$MODE" = public ] && [ -z "$DOMAIN" ] && echo "  Note:     self-signed certificate — the browser warns once; use --domain for a trusted one."
[ "$MODE" = public ] && echo "  Cloud:    also allow ports 80 and 443 in your provider's firewall / security group."
echo
if [ "$has_systemd" = 1 ] && [ "$SERVICE" = 1 ]; then
  echo "  Status:   sudo systemctl status bloody        Logs:  journalctl -u bloody -f"
  echo "  Restart:  sudo systemctl restart bloody       Check: bash scripts/doctor.sh"
else
  echo "  Logs:     tail -f logs/bloody.log             Check: bash scripts/doctor.sh"
  echo "  Restart:  ./install.sh"
fi
echo "  Update:   git pull && ./install.sh"
[ "$doctor_ok" = 1 ]
