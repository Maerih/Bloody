#!/usr/bin/env bash
# SCIAT Agent installer for Linux and macOS — proprietary, (c) SCIAT AFRICA.
#
#   curl -fsSL __PLATFORM_URL__/api/v1/agent/install/linux -o install-sciat.sh
#   sudo bash install-sciat.sh --account-key sak_… --org-key <organization key>
#   sudo bash install-sciat.sh --uninstall
#
# Installs the agent as a service named after us:
#   Linux  systemd unit  sciat-agent.service  ("SCIAT Agent")
#   macOS  LaunchDaemon  africa.sciat.agent
# The platform address below is filled in by the platform that served this script.
set -euo pipefail

PLATFORM_URL="${SCIAT_PLATFORM_URL:-__PLATFORM_URL__}"
AGENT_VERSION="1.4.0"
PREFIX="/opt/sciat-agent"
OS="$(uname -s)"
if [ "$OS" = Darwin ]; then
  CONF_DIR="/Library/Application Support/SCIAT"
  PLIST="/Library/LaunchDaemons/africa.sciat.agent.plist"
else
  CONF_DIR="/etc/sciat-agent"
  UNIT="/etc/systemd/system/sciat-agent.service"
fi

say() { printf '\033[1;31mSCIAT\033[0m %s\n' "$*"; }
die() { printf 'SCIAT agent install: %s\n' "$*" >&2; exit 1; }
usage() { echo "usage: $0 --account-key <sak_…> --org-key <organization key> | --uninstall"; exit 2; }

ACCOUNT_KEY="" ORG_KEY="" UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --account-key) ACCOUNT_KEY="${2:-}"; shift 2 ;;
    --org-key|--organization-key) ORG_KEY="${2:-}"; shift 2 ;;
    --platform-url) PLATFORM_URL="${2:-}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown option $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

stop_service() {
  if [ "$OS" = Darwin ]; then
    launchctl bootout system/africa.sciat.agent 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null || true
  elif command -v systemctl >/dev/null; then
    systemctl disable --now sciat-agent.service 2>/dev/null || true
  fi
}

if [ "$UNINSTALL" -eq 1 ]; then
  stop_service
  [ -x "$PREFIX/bloody-isolate" ] && "$PREFIX/bloody-isolate" release 2>/dev/null || true
  rm -f "${UNIT:-}" "${PLIST:-}"
  command -v systemctl >/dev/null && [ "$OS" != Darwin ] && systemctl daemon-reload || true
  rm -rf "$PREFIX" "$CONF_DIR"
  say "SCIAT Agent removed."
  exit 0
fi

[ -n "$ACCOUNT_KEY" ] && [ -n "$ORG_KEY" ] || usage
[[ "$ACCOUNT_KEY" =~ ^sak_[0-9a-f]{32}_[A-Za-z0-9_-]{32,64}$ ]] || die "the account key looks wrong (expected sak_…)"
[[ "$ORG_KEY" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$ ]] || die "the organization key looks wrong"
url_re='^https?://[]A-Za-z0-9.:[_-]+(/[A-Za-z0-9._~/-]*)?$'
[[ "$PLATFORM_URL" =~ $url_re ]] || die "invalid platform URL '$PLATFORM_URL'"
PLATFORM_URL="${PLATFORM_URL%/}"
command -v curl >/dev/null || die "curl is required"

js() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; printf '"%s"' "$s"; }
host="$(hostname)"
if [ "$OS" = Darwin ]; then
  platform=macos; os_name="macOS $(sw_vers -productVersion 2>/dev/null)"
  machine_id="$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/ {print $4}')"
else
  platform=linux; os_name="$( (. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-Linux}") || uname -sr)"
  machine_id="$(cat /etc/machine-id 2>/dev/null || true)"
fi
ips=""
if command -v ip >/dev/null; then
  ips="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -16 | while read -r a; do printf '%s,' "$(js "$a")"; done)"
elif command -v ifconfig >/dev/null; then
  ips="$(ifconfig 2>/dev/null | awk '/inet / && $2 != "127.0.0.1" {print $2}' | head -16 | while read -r a; do printf '%s,' "$(js "$a")"; done)"
fi
body="{\"accountKey\":$(js "$ACCOUNT_KEY"),\"organizationKey\":$(js "$ORG_KEY"),\"hostname\":$(js "$host"),\"platform\":\"$platform\",\"os\":$(js "$os_name"),\"version\":\"$AGENT_VERSION\",\"ips\":[${ips%,}]"
[ -n "$machine_id" ] && body="$body,\"machineId\":$(js "$machine_id")"
body="$body}"

say "Enrolling $host with $PLATFORM_URL …"
resp="$(curl -sS --max-time 30 -X POST "$PLATFORM_URL/api/v1/agent/enroll" -H 'content-type: application/json' --data-binary "$body" -w '\n%{http_code}')" || die "cannot reach $PLATFORM_URL"
code="${resp##*$'\n'}"; resp="${resp%$'\n'*}"
if [ "$code" != 200 ] && [ "$code" != 201 ]; then
  msg="$(printf '%s' "$resp" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p')"
  die "enrollment refused (HTTP $code): ${msg:-$resp}"
fi
token="$(printf '%s' "$resp" | grep -o '"token":"sat_[A-Za-z0-9_-]*"' | cut -d'"' -f4)"
[ -n "$token" ] || die "the platform did not return an agent token"

say "Installing files to $PREFIX …"
mkdir -p "$PREFIX" "$CONF_DIR"
fetch() { curl -fsS --max-time 60 "$PLATFORM_URL/api/v1/agent/files/$1" -o "$2" || die "download of $1 failed"; }
fetch sciat-agent.sh "$PREFIX/sciat-agent.new" && mv "$PREFIX/sciat-agent.new" "$PREFIX/sciat-agent"
chmod 0755 "$PREFIX/sciat-agent"
# Network isolation: nftables on Linux, the built-in pf firewall on macOS (same commands).
if [ "$platform" = linux ]; then
  fetch bloody-isolate "$PREFIX/bloody-isolate.new" && mv "$PREFIX/bloody-isolate.new" "$PREFIX/bloody-isolate"
else
  fetch bloody-isolate-macos "$PREFIX/bloody-isolate.new" && mv "$PREFIX/bloody-isolate.new" "$PREFIX/bloody-isolate"
fi
chmod 0750 "$PREFIX/bloody-isolate"
umask 077
printf "PLATFORM_URL='%s'\nAGENT_TOKEN='%s'\n" "$PLATFORM_URL" "$token" > "$CONF_DIR/agent.conf"
chmod 0600 "$CONF_DIR/agent.conf"

stop_service
if [ "$OS" = Darwin ]; then
  cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>africa.sciat.agent</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$PREFIX/sciat-agent</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/Library/Logs/sciat-agent.log</string>
</dict></plist>
PLIST
  chmod 0644 "$PLIST"
  launchctl bootstrap system "$PLIST" 2>/dev/null || launchctl load -w "$PLIST"
else
  command -v systemctl >/dev/null || die "systemd is required (start '$PREFIX/sciat-agent run' from your init system instead)"
  cat > "$UNIT" <<UNIT
[Unit]
Description=SCIAT Agent
Documentation=https://sciat.africa
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash $PREFIX/sciat-agent run
Restart=always
RestartSec=15
SyslogIdentifier=sciat-agent

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now sciat-agent.service
fi

if "$PREFIX/sciat-agent" once >/dev/null 2>&1; then
  say "SCIAT Agent installed and checked in. It now appears under Agents in the Command Center."
else
  say "SCIAT Agent installed; the first check-in failed — see 'journalctl -u sciat-agent' (Linux) or /Library/Logs/sciat-agent.log (macOS)."
fi
