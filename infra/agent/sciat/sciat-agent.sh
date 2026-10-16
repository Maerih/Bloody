#!/usr/bin/env bash
# SCIAT Agent (Linux / macOS) — proprietary, (c) SCIAT AFRICA.
# Checks in with the SCIAT / Bloody platform: liveness, host facts, isolation state, engines.
# Runs as the `sciat-agent` service (systemd) or `africa.sciat.agent` (launchd).
#
#   sciat-agent run        # service loop (default)
#   sciat-agent once       # one check-in, prints the platform's answer
#   sciat-agent status     # configuration and last check-in
set -uo pipefail

AGENT_VERSION="1.0.0"
CONF="${SCIAT_AGENT_CONF:-/etc/sciat-agent/agent.conf}"
[ "$(uname -s)" = Darwin ] && CONF="${SCIAT_AGENT_CONF:-/Library/Application Support/SCIAT/agent.conf}"
STATE_DIR="$(dirname "$CONF")"
LOG_TAG="sciat-agent"

log() { if command -v logger >/dev/null; then logger -t "$LOG_TAG" -- "$*"; fi; echo "$(date -u +%FT%TZ) $*" >&2; }

# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"
: "${PLATFORM_URL:?PLATFORM_URL missing in $CONF — reinstall the agent}"
: "${AGENT_TOKEN:?AGENT_TOKEN missing in $CONF — reinstall the agent}"

json_escape() { # stdin → JSON string body (no surrounding quotes)
  local s; s="$(cat)"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\r'/}"; s="${s//$'\t'/ }"
  printf '%s' "$s"
}
js() { printf '"%s"' "$(printf '%s' "$1" | json_escape)"; }

os_name() {
  if [ "$(uname -s)" = Darwin ]; then echo "macOS $(sw_vers -productVersion 2>/dev/null)"; return; fi
  if [ -r /etc/os-release ]; then (. /etc/os-release; echo "${PRETTY_NAME:-Linux}"); else uname -sr; fi
}
ip_list() {
  if command -v ip >/dev/null; then ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1
  elif command -v ifconfig >/dev/null; then ifconfig 2>/dev/null | awk '/inet / && $2 != "127.0.0.1" {print $2}'
  fi | head -16
}
uptime_seconds() {
  if [ -r /proc/uptime ]; then cut -d. -f1 /proc/uptime
  else local boot; boot="$(sysctl -n kern.boottime 2>/dev/null | sed -nE 's/.*sec = ([0-9]+).*/\1/p')"; [ -n "$boot" ] && echo $(( $(date +%s) - boot )) || echo 0; fi
}
isolation_json() {
  local iso="/opt/sciat-agent/bloody-isolate"
  if [ -x "$iso" ]; then
    local out; out="$("$iso" status 2>/dev/null || true)"
    if [ "${out%%$'\n'*}" = isolated ]; then
      local mode; mode="$(printf '%s\n' "$out" | sed -n 's/^mode=//p' | head -1)"
      printf '{"state":"isolated","mode":%s}' "$(js "${mode:-unknown}")"; return
    fi
    printf '{"state":"not_isolated"}'; return
  fi
  printf '{"state":"unknown"}'
}
engines_json() {
  local parts=()
  if command -v systemctl >/dev/null; then
    for svc in wazuh-agent osqueryd falcon-sensor velociraptor_client; do
      if systemctl list-unit-files "$svc.service" >/dev/null 2>&1 && systemctl list-unit-files "$svc.service" | grep -q "$svc"; then
        parts+=("$(js "$svc"):$(js "$(systemctl is-active "$svc" 2>/dev/null || echo unknown)")")
      fi
    done
  fi
  local IFS=,; printf '{%s}' "${parts[*]}"
}

ISOLATE="/opt/sciat-agent/bloody-isolate"
IP_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9A-Fa-f]*:[0-9A-Fa-f:]+$'
platform_host() { local h="${PLATFORM_URL#*://}"; h="${h%%/*}"; if [[ "$h" == \[* ]]; then h="${h#[}"; h="${h%%]*}"; else h="${h%%:*}"; fi; printf '%s' "$h"; }
platform_port() { local h="${PLATFORM_URL#*://}"; h="${h%%/*}"; h="${h##*]}"; if [[ "$h" == *:* ]]; then echo "${h##*:}"; elif [[ "$PLATFORM_URL" == https:* ]]; then echo 443; else echo 80; fi; }
# Addresses of the platform: they stay reachable when this endpoint is isolated (cached, so the
# agent keeps working when DNS is unreachable during full isolation).
platform_ips() {
  local h ips=""; h="$(platform_host)"
  if [[ "$h" =~ $IP_RE ]]; then ips="$h"
  elif command -v getent >/dev/null; then ips="$(getent ahosts "$h" 2>/dev/null | awk '{print $1}' | sort -u | head -8)"
  elif command -v dscacheutil >/dev/null; then ips="$(dscacheutil -q host -a name "$h" 2>/dev/null | awk '/ip_address/ {print $2}' | sort -u | head -8)"
  fi
  if [ -n "$ips" ]; then printf '%s\n' "$ips" > "$STATE_DIR/platform-ips" 2>/dev/null || true; printf '%s\n' "$ips"
  elif [ -r "$STATE_DIR/platform-ips" ]; then cat "$STATE_DIR/platform-ips"; fi
}
dns_servers() {
  { if command -v resolvectl >/dev/null; then resolvectl dns 2>/dev/null | tr ' ' '\n'; fi
    awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null; } | grep -E "$IP_RE" | grep -vE '^(127\.|::1$)' | sort -u | head -8
}
json_list() { local out=() v; while IFS= read -r v; do [ -n "$v" ] && out+=("$(js "$v")"); done; local IFS=,; printf '[%s]' "${out[*]}"; }

# While isolated, reach the platform by its cached address (DNS may be blocked).
curl_pin() {
  local h; h="$(platform_host)"
  if [[ ! "$h" =~ $IP_RE ]] && [ -r "$STATE_DIR/platform-ips" ] && [ -x "$ISOLATE" ] && [ "$("$ISOLATE" status 2>/dev/null | head -1)" = isolated ]; then
    printf -- '--resolve\n%s:%s:%s\n' "$h" "$(platform_port)" "$(head -1 "$STATE_DIR/platform-ips")"
  fi
}
api() { # api <path> <json body>
  local pin=(); mapfile -t pin < <(curl_pin)
  curl -fsS --max-time 20 "${pin[@]}" -X POST "$PLATFORM_URL/api/v1$1" \
    -H "authorization: Bearer $AGENT_TOKEN" -H "content-type: application/json" --data-binary "$2"
}

checkin() {
  local ips=() ip
  while IFS= read -r ip; do [ -n "$ip" ] && ips+=("$(js "$ip")"); done < <(ip_list)
  local IFS=,
  local body
  body="{\"hostname\":$(js "$(hostname)"),\"os\":$(js "$(os_name)"),\"version\":$(js "$AGENT_VERSION"),\"ips\":[${ips[*]}],\"uptimeSeconds\":$(uptime_seconds),\"isolation\":$(isolation_json),\"engines\":$(engines_json),\"platformIps\":$(platform_ips | json_list),\"dnsServers\":$(dns_servers | json_list)}"
  api /agent/heartbeat "$body"
}

# Commands from the platform arrive as plain lines "<id> <args…>" (commandLines). Only
# isolate / release are accepted, and only with address-like arguments.
run_commands() {
  local block line id rest out rc status ran=1
  block="$(printf '%s' "$1" | grep -o '"commandLines":\[[^]]*\]' | sed -e 's/^"commandLines":\[//' -e 's/\]$//')"
  [ -n "$block" ] || return 1
  while IFS= read -r line; do
    line="${line#\"}"; line="${line%\"}"
    id="${line%% *}"; rest="${line#* }"
    [[ "$id" =~ ^[0-9a-f-]{36}$ ]] || continue
    local args=(); read -r -a args <<< "$rest"
    if [[ ! "${args[0]:-}" =~ ^(isolate|release)$ ]] || [[ ! "$rest" =~ ^[A-Za-z0-9.,:=/_\ -]+$ ]]; then
      out="refused: unexpected command"; rc=2
    elif [ "$(uname -s)" = Darwin ] || [ ! -x "$ISOLATE" ]; then
      out="isolation is not available on this endpoint"; rc=3
    else
      out="$("$ISOLATE" "${args[@]}" 2>&1 </dev/null)"; rc=$?
      if [ $rc -eq 0 ]; then out="$out"$'\n'"$("$ISOLATE" status 2>&1)"; fi
    fi
    status=failed; [ $rc -eq 0 ] && status=succeeded
    log "command ${args[0]:-?} ($id): $status"
    api "/agent/commands/$id/result" "{\"status\":\"$status\",\"output\":$(js "${out:0:4000}")}" >/dev/null || log "could not report command $id"
    ran=0
  done < <(printf '%s\n' "$block" | sed 's/","/\n/g')
  return $ran
}

case "${1:-run}" in
  once) resp="$(checkin)" && { printf '%s\n' "$resp"; run_commands "$resp" || true; } ;;
  status)
    echo "SCIAT Agent $AGENT_VERSION"
    echo "platform: $PLATFORM_URL"
    [ -r "$STATE_DIR/last-checkin" ] && echo "last check-in: $(cat "$STATE_DIR/last-checkin")" || echo "last check-in: never"
    ;;
  run)
    log "starting (version $AGENT_VERSION, platform $PLATFORM_URL)"
    delay=60 failures=0
    while true; do
      if resp="$(checkin 2>&1)"; then
        failures=0
        date -u +%FT%TZ > "$STATE_DIR/last-checkin" 2>/dev/null || true
        poll="$(printf '%s' "$resp" | grep -o '"pollSeconds":[0-9]*' | cut -d: -f2)"
        delay="${poll:-60}"
        # Ran a command: check in again soon so the platform sees the new state.
        if run_commands "$resp"; then delay=5; fi
      else
        failures=$((failures + 1))
        # Back off while the platform is unreachable (max 10 minutes), log every few attempts.
        delay=$(( 60 * (failures < 10 ? failures : 10) ))
        [ $((failures % 5)) -eq 1 ] && log "check-in failed ($failures in a row): ${resp:0:200}"
      fi
      sleep "$delay"
    done
    ;;
  *) echo "usage: sciat-agent [run|once|status]" >&2; exit 2 ;;
esac
