#!/usr/bin/env bash
# Bloody — one-command install on a fresh Linux server (Ubuntu/Debian, Fedora/RHEL/Rocky/Alma).
#
#   git clone <repo> bloody && cd bloody && git switch maerih/bloody
#   ./install.sh
#
# It checks everything and installs what is missing: Node.js 22, pnpm, PostgreSQL; creates the
# database and a private .env (random passwords and secrets); installs dependencies; migrates;
# loads demo data; installs the `bloody` service (starts on boot, restarts on failure); opens the
# firewall port; and finishes with a full health check (scripts/doctor.sh). Safe to re-run: re-run
# it after `git pull` or when the server's IP changed.
#
# Options:
#   --ip <addr>        address users open in the browser (default: auto-detected)
#   --no-service       do not install the systemd service (run scripts/start-demo.sh yourself)
#   --no-demo-data     do not load the demo customers, incidents and logins
#   -h, --help
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(pwd)"
export PATH="/usr/local/bin:$PATH"
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0 CI=true

IP="" SERVICE=1 SEED=1
while [ $# -gt 0 ]; do
  case "$1" in
    --ip) IP="${2:?--ip needs an address}"; shift ;;
    --ip=*) IP="${1#--ip=}" ;;
    --no-service) SERVICE=0 ;;
    --no-demo-data) SEED=0 ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

if [ -t 1 ]; then B=$'\e[1m'; G=$'\e[32m'; R=$'\e[31m'; N=$'\e[0m'; else B=""; G=""; R=""; N=""; fi
step() { echo; echo "${B}==> $*${N}"; }
die() { echo "${R}error:${N} $*" >&2; exit 1; }

if [ "$(id -u)" = 0 ]; then SUDO=""; else
  command -v sudo >/dev/null || die "run as root or install sudo"
  SUDO="sudo"; $SUDO -v || die "sudo access is required to install system packages"
fi
RUN_USER="$(stat -c %U "$REPO")"
as_owner() { if [ "$(id -un)" = "$RUN_USER" ]; then "$@"; else $SUDO -u "$RUN_USER" -H env PATH="$PATH" COREPACK_ENABLE_DOWNLOAD_PROMPT=0 CI=true "$@"; fi; }

# ─── 1. Operating system & base tools ────────────────────────────────────────
step "Checking the system"
[ "$(uname -s)" = Linux ] || die "Linux is required"
. /etc/os-release 2>/dev/null || true
echo "    ${PRETTY_NAME:-Linux} ($(uname -m)), user $RUN_USER"
if command -v apt-get >/dev/null; then PM=apt
elif command -v dnf >/dev/null; then PM=dnf
elif command -v yum >/dev/null; then PM=yum
else die "unsupported distribution (needs apt, dnf or yum). Install Node.js 22, pnpm and PostgreSQL 14+ manually, then run: bash scripts/setup-local.sh"; fi

pkg_install() {
  case "$PM" in
    apt) $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" ;;
    *) $SUDO "$PM" install -y -q "$@" ;;
  esac
}
missing=()
for tool in curl git xz tar; do command -v "$tool" >/dev/null || missing+=("$tool"); done
if [ ${#missing[@]} -gt 0 ]; then
  echo "    installing: ${missing[*]}"
  [ "$PM" = apt ] && $SUDO apt-get update -q
  pkgs=(); for t in "${missing[@]}"; do case "$t" in xz) [ "$PM" = apt ] && pkgs+=(xz-utils) || pkgs+=(xz) ;; *) pkgs+=("$t") ;; esac; done
  pkg_install ca-certificates "${pkgs[@]}"
fi

# ─── 2. Node.js 22 ───────────────────────────────────────────────────────────
step "Node.js"
node_major() { node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0; }
if [ "$(node_major)" -ge 22 ]; then
  echo "    Node.js $(node -v) ✔"
else
  echo "    found $(node -v 2>/dev/null || echo 'no Node.js'); installing the official Node.js 22 build into /usr/local"
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
  echo "    Node.js $(node -v) ✔"
fi

# ─── 3. pnpm (version pinned by package.json) ────────────────────────────────
step "pnpm"
want_pnpm="$(node -p 'require("./package.json").packageManager.split("@")[1]')"
if [ "$(pnpm -v 2>/dev/null || true)" != "$want_pnpm" ]; then
  echo "    activating pnpm $want_pnpm via corepack"
  $SUDO env PATH="$PATH" COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack enable --install-directory "$(dirname "$(command -v node)")" ||
    $SUDO env PATH="$PATH" npm install -g --silent "pnpm@$want_pnpm"
  as_owner corepack prepare "pnpm@$want_pnpm" --activate >/dev/null 2>&1 || true
  hash -r
fi
command -v pnpm >/dev/null || die "pnpm could not be installed"
echo "    pnpm $(as_owner pnpm -v) ✔"

# ─── 4. PostgreSQL ───────────────────────────────────────────────────────────
step "PostgreSQL"
if ! command -v psql >/dev/null || ! { [ -d /etc/postgresql ] || [ -d /var/lib/pgsql ] || command -v pg_ctl >/dev/null || ls /usr/lib/postgresql/*/bin/postgres >/dev/null 2>&1; }; then
  echo "    installing PostgreSQL"
  if [ "$PM" = apt ]; then
    $SUDO apt-get update -q
    pkg_install postgresql postgresql-contrib
  else
    pkg_install postgresql-server postgresql-contrib
    [ -f /var/lib/pgsql/data/PG_VERSION ] || $SUDO postgresql-setup --initdb
    # Allow password logins over localhost TCP (Fedora/RHEL default is ident).
    $SUDO sed -i -E 's#^(host\s+all\s+all\s+(127\.0\.0\.1/32|::1/128)\s+)ident#\1scram-sha-256#' /var/lib/pgsql/data/pg_hba.conf
  fi
fi
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
  $SUDO systemctl enable --now postgresql >/dev/null 2>&1 || true
else
  $SUDO service postgresql start >/dev/null 2>&1 || true
fi
echo "    $(psql --version) ✔"

# ─── 5. Database, .env, dependencies, migrations, demo data ──────────────────
step "Setting up Bloody (database, .env, dependencies, migrations$([ "$SEED" = 1 ] && echo ', demo data'))"
setup_env=(BLOODY_SEED="$SEED")
[ -n "$IP" ] && setup_env+=(BLOODY_IP="$IP")
as_owner env "${setup_env[@]}" bash scripts/setup-local.sh
IP="$(grep -E '^PUBLIC_URL=' .env | sed -E 's#^PUBLIC_URL=https?://([^:/]+).*#\1#')"

# ─── 6. Service ──────────────────────────────────────────────────────────────
has_systemd=0; command -v systemctl >/dev/null && [ -d /run/systemd/system ] && has_systemd=1
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
  echo "    building the UI and starting (first start takes a minute) ..."
  for _ in $(seq 1 180); do
    curl -fsS --noproxy '*' -o /dev/null http://127.0.0.1:5173/ 2>/dev/null && curl -fsS --noproxy '*' -o /dev/null http://127.0.0.1:4000/api/v1/healthz 2>/dev/null && break
    systemctl is-failed --quiet bloody && break
    sleep 2
  done
elif [ "$SERVICE" = 1 ]; then
  # No systemd (container, WSL …): start in the background now; it will not survive a reboot.
  step "Starting Bloody in the background (no systemd: re-run ./install.sh after a reboot)"
  mkdir -p logs && chown "$RUN_USER" logs
  if [ -f logs/bloody.pid ] && kill -0 "$(cat logs/bloody.pid)" 2>/dev/null; then
    echo "    stopping the previous run"
    kill -TERM -- "-$(cat logs/bloody.pid)" 2>/dev/null || true
    for _ in $(seq 1 15); do kill -0 "$(cat logs/bloody.pid)" 2>/dev/null || break; sleep 1; done
  fi
  rm -f logs/bloody.pid
  as_owner env BLOODY_PIDFILE="$REPO/logs/bloody.pid" setsid nohup bash scripts/start-demo.sh --prod > logs/bloody.log 2>&1 < /dev/null &
  for _ in $(seq 1 10); do [ -s logs/bloody.pid ] && break; sleep 0.5; done
  echo "    building the UI and starting (first start takes a minute) ..."
  for _ in $(seq 1 180); do
    curl -fsS --noproxy '*' -o /dev/null http://127.0.0.1:5173/ 2>/dev/null && curl -fsS --noproxy '*' -o /dev/null http://127.0.0.1:4000/api/v1/healthz 2>/dev/null && break
    kill -0 "$(cat logs/bloody.pid)" 2>/dev/null || break
    sleep 2
  done
fi

# ─── 7. Firewall ─────────────────────────────────────────────────────────────
if command -v ufw >/dev/null && $SUDO ufw status 2>/dev/null | grep -q "Status: active"; then
  step "Firewall: allowing port 5173 (ufw)"; $SUDO ufw allow 5173/tcp >/dev/null
elif command -v firewall-cmd >/dev/null && $SUDO firewall-cmd --state >/dev/null 2>&1; then
  step "Firewall: allowing port 5173 (firewalld)"; $SUDO firewall-cmd --permanent --add-port=5173/tcp >/dev/null && $SUDO firewall-cmd --reload >/dev/null
fi

# ─── 8. Health check ─────────────────────────────────────────────────────────
step "Health check"
doctor_ok=1
as_owner bash scripts/doctor.sh || doctor_ok=0

echo
if [ "$doctor_ok" = 1 ]; then echo "${G}${B}Bloody is installed.${N}"; else echo "${R}${B}Installed, but the health check found problems (see above).${N}"; fi
cat <<EOF

  Open:   http://${IP}:5173
$([ "$SEED" = 1 ] && echo "  Login:  admin@bloody.local / ChangeMe!123   (change it after the first login)")

$(if [ "$has_systemd" = 1 ] && [ "$SERVICE" = 1 ]; then
  echo "  Status:   sudo systemctl status bloody        Logs:  journalctl -u bloody -f"
  echo "  Restart:  sudo systemctl restart bloody       Check: bash scripts/doctor.sh"
else
  echo "  Logs:     tail -f logs/bloody.log             Check: bash scripts/doctor.sh"
  echo "  Restart:  ./install.sh"
fi)
  Update:   git pull && ./install.sh
EOF
[ "$doctor_ok" = 1 ]
