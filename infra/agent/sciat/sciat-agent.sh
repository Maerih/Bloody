#!/usr/bin/env bash
# SCIAT Agent (Linux / macOS) — proprietary, (c) SCIAT AFRICA.
# Checks in with the SCIAT / Bloody platform: liveness, host facts, isolation state, engines.
# Runs as the `sciat-agent` service (systemd) or `africa.sciat.agent` (launchd).
#
#   sciat-agent run        # service loop (default)
#   sciat-agent once       # one check-in, prints the platform's answer
#   sciat-agent status     # configuration and last check-in
#   sciat-agent inventory  # print the host inventory (software, services, users, processes, ports, AV)
set -uo pipefail

AGENT_VERSION="1.3.0"
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
    if command -v scutil >/dev/null; then scutil --dns 2>/dev/null | awk '/nameserver\[[0-9]+\]/ {print $3}'; fi
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
  local pin=() l; while IFS= read -r l; do pin+=("$l"); done < <(curl_pin)
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
# Attack Reduction fixes the platform may ask for (Response action "harden_endpoint", approved by a
# person). Only these built-in routines run; the platform never sends script text.
harden_fix() {
  case "$1" in
    linux_aslr)
      [ "$(uname -s)" = Linux ] || { echo "not a Linux endpoint"; return 3; }
      printf 'kernel.randomize_va_space = 2\n' > /etc/sysctl.d/60-sciat-aslr.conf && sysctl -q -w kernel.randomize_va_space=2 && echo "ASLR set to full (2)" ;;
    mac_gatekeeper)
      [ "$(uname -s)" = Darwin ] || { echo "not a macOS endpoint"; return 3; }
      { spctl --master-enable 2>/dev/null || spctl --global-enable; } && echo "Gatekeeper enabled" ;;
    mac_guest)
      [ "$(uname -s)" = Darwin ] || { echo "not a macOS endpoint"; return 3; }
      defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false && echo "Guest user disabled" ;;
    mac_auto_updates)
      [ "$(uname -s)" = Darwin ] || { echo "not a macOS endpoint"; return 3; }
      defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true \
        && defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true \
        && echo "Security responses and system data files install automatically" ;;
    *) echo "no built-in fix for $1"; return 3 ;;
  esac
}

run_commands() {
  local block line id rest out rc status ran=1
  block="$(printf '%s' "$1" | grep -o '"commandLines":\[[^]]*\]' | sed -e 's/^"commandLines":\[//' -e 's/\]$//')"
  [ -n "$block" ] || return 1
  while IFS= read -r line; do
    line="${line#\"}"; line="${line%\"}"
    id="${line%% *}"; rest="${line#* }"
    [[ "$id" =~ ^[0-9a-f-]{36}$ ]] || continue
    local args=(); read -r -a args <<< "$rest"
    if [[ ! "${args[0]:-}" =~ ^(isolate|release|harden)$ ]] || [[ ! "$rest" =~ ^[A-Za-z0-9.,:=/_\ -]+$ ]]; then
      out="refused: unexpected command"; rc=2
    elif [ "${args[0]}" = harden ]; then
      if [ "${#args[@]}" -ne 2 ] || [[ ! "${args[1]}" =~ ^[a-z0-9_]{1,40}$ ]]; then out="refused: unexpected command"; rc=2
      else
        out="$(harden_fix "${args[1]}" 2>&1 </dev/null)"; rc=$?
        # Re-report straight away so the platform re-grades the computer.
        [ $rc -eq 0 ] && { send_inventory >/dev/null 2>&1 || log "inventory upload failed"; }
      fi
    elif [ ! -x "$ISOLATE" ]; then
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

# ---- Host inventory (about every 30 minutes) -------------------------------------------------
# tsv_json "name,version,#port,?admin" : tab-separated stdin → JSON array; empty → null,
# "#" marks numbers, "?" booleans (1/true/yes). One awk pass, so thousands of rows stay cheap.
tsv_json() {
  awk -F'\t' -v spec="$1" -v max="${2:-5000}" '
    function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); gsub(/[\001-\037]/, " ", s); return s }
    BEGIN { n = split(spec, f, ","); printf "["; c = 0 }
    NF > 0 && c < max {
      printf "%s{", (c++ ? "," : "")
      for (i = 1; i <= n; i++) {
        k = f[i]; v = $i; t = substr(k, 1, 1)
        if (t == "#" || t == "?") k = substr(k, 2)
        printf "%s\"%s\":", (i > 1 ? "," : ""), k
        if (t == "#") printf "%s", (v ~ /^[0-9]+$/ ? v : "0")
        else if (t == "?") printf "%s", (v ~ /^(1|true|yes)$/ ? "true" : "false")
        else if (v == "") printf "null"
        else printf "\"%s\"", esc(v)
      }
      printf "}"
    }
    END { printf "]" }'
}

inv_software() {
  if command -v dpkg-query >/dev/null; then dpkg-query -W -f='${Package}\t${Version}\t${Maintainer}\n' 2>/dev/null
  elif command -v rpm >/dev/null; then rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n' 2>/dev/null
  elif [ "$(uname -s)" = Darwin ]; then
    for app in /Applications/*.app; do
      [ -d "$app" ] || continue
      printf '%s\t%s\t\n' "$(basename "$app" .app)" "$(defaults read "$app/Contents/Info" CFBundleShortVersionString 2>/dev/null)"
    done
  fi | sort -u | tsv_json "name,version,publisher" 5000
}

inv_services() {
  if command -v systemctl >/dev/null; then
    local modes; modes="$(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{print $1"\t"$2}')"
    systemctl list-units --type=service --all --no-legend --no-pager --plain 2>/dev/null |
      awk -v modes="$modes" '
        BEGIN { n = split(modes, m, "\n"); for (i = 1; i <= n; i++) { split(m[i], p, "\t"); st = p[2]; mode[p[1]] = (st == "enabled" ? "auto" : st == "disabled" || st == "masked" ? "disabled" : "manual") } }
        { unit = $1; sub(/\.service$/, "", unit); desc = ""; for (i = 5; i <= NF; i++) desc = desc (i > 5 ? " " : "") $i
          printf "%s\t%s\t%s\t%s\t\n", unit, desc, $4, mode[$1] }'
  elif [ "$(uname -s)" = Darwin ]; then
    launchctl list 2>/dev/null | awk 'NR > 1 { printf "%s\t\t%s\t\t\n", $3, ($1 == "-" ? "stopped" : "running") }'
  fi | tsv_json "name,displayName,state,startMode,account" 2000
}

inv_users() {
  local online; online=" $(who 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ') "
  if [ "$(uname -s)" = Darwin ]; then
    dscl . list /Users UniqueID 2>/dev/null | awk '$2 >= 500 || $2 == 0 {print $1}' | while read -r u; do
      local adm=0; dseditgroup -o checkmember -m "$u" admin >/dev/null 2>&1 && adm=1
      printf '%s\t%s\t%s\t1\t%s\n' "$u" "$(dscl . -read "/Users/$u" RealName 2>/dev/null | tail -1 | sed 's/^ *//')" "$adm" "$([[ "$online" == *" $u "* ]] && echo 1 || echo 0)"
    done
  else
    getent passwd 2>/dev/null || cat /etc/passwd
  fi | if [ "$(uname -s)" = Darwin ]; then cat; else
    awk -F: '($3 == 0 || $3 >= 1000) && $3 != 65534 { print $1"\t"$5"\t"$7 }' | while IFS=$'\t' read -r u name shell; do
      local adm=0 enabled=1
      id -nG "$u" 2>/dev/null | grep -qwE 'sudo|wheel|admin|root' && adm=1
      [ "$u" = root ] && adm=1
      # Only accounts that can log in (system accounts without a shell are noise here).
      case "$shell" in */nologin|*/false|*/sync|"") continue ;; esac
      printf '%s\t%s\t%s\t%s\t%s\n' "$u" "${name%%,*}" "$adm" "$enabled" "$([[ "$online" == *" $u "* ]] && echo 1 || echo 0)"
    done
  fi | tsv_json "name,fullName,?admin,?enabled,?loggedIn" 1000
}

inv_processes() {
  ps -eo pid=,user=,comm= 2>/dev/null | while read -r pid user comm; do
    local path=""; [ -r "/proc/$pid/exe" ] || [ -e "/proc/$pid/exe" ] && path="$(readlink "/proc/$pid/exe" 2>/dev/null)"
    [ "$(uname -s)" = Darwin ] && path="$comm"
    printf '%s\t%s\t%s\t%s\n' "$pid" "$(basename "${path:-$comm}")" "$path" "$user"
  done | tsv_json "#pid,name,path,user" 2000
}

inv_ports() {
  if command -v ss >/dev/null; then
    ss -Htulnp 2>/dev/null | awk '{ local = $5; port = local; sub(/.*:/, "", port); addr = local; sub(/:[^:]*$/, "", addr); gsub(/[\[\]]/, "", addr)
      proc = ""; if (match($0, /users:\(\("[^"]+"/)) { proc = substr($0, RSTART + 9, RLENGTH - 10) }
      if (port ~ /^[0-9]+$/) printf "%s\t%s\t%s\t%s\n", $1, addr, port, proc }'
  elif command -v lsof >/dev/null; then
    lsof +c 0 -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR > 1 { a = $9; port = a; sub(/.*:/, "", port); addr = a; sub(/:[^:]*$/, "", addr); printf "tcp\t%s\t%s\t%s\n", addr, port, $1 }'
  fi | sort -u | tsv_json "protocol,address,#port,process" 2000
}

# Antivirus: Microsoft Defender for Endpoint (mdatp), ClamAV, CrowdStrike, SentinelOne, Sophos; XProtect on macOS.
inv_antivirus() {
  local now; now="$(date +%s)"
  {
    if command -v mdatp >/dev/null; then
      local rtp defs; rtp="$(mdatp health --field real_time_protection_enabled 2>/dev/null | tr -d ' "')"; defs="$(mdatp health --field definitions_status 2>/dev/null | tr -d '"')"
      printf 'Microsoft Defender for Endpoint\t%s\t%s\t%s\t\t\n' "$(mdatp health --field healthy 2>/dev/null | tr -d ' ')" "$([[ "$defs" == *up_to_date* ]] && echo true || echo false)" "$rtp"
    fi
    if command -v systemctl >/dev/null; then
      for unit in clamav-daemon clamd@scan clamd; do
        if systemctl list-unit-files "$unit.service" 2>/dev/null | grep -q "$unit"; then
          local db age=""; db="$(ls -t /var/lib/clamav/daily.c?d /var/lib/clamav/main.c?d 2>/dev/null | head -1)"
          [ -n "$db" ] && age=$(( (now - $(stat -c %Y "$db")) / 86400 ))
          local onacc=""; systemctl list-unit-files clamav-clamonacc.service 2>/dev/null | grep -q clamonacc && { systemctl is-active --quiet clamav-clamonacc && onacc=true || onacc=false; }
          printf 'ClamAV\t%s\t\t%s\t\t%s\n' "$(systemctl is-active --quiet "$unit" && echo true || echo false)" "$onacc" "$age"
          break
        fi
      done
      for pair in "falcon-sensor:CrowdStrike Falcon" "sentinelone:SentinelOne" "sophos-spl:Sophos Protection" "eset_rtp:ESET Endpoint Antivirus"; do
        local unit="${pair%%:*}" label="${pair#*:}"
        systemctl list-unit-files "$unit.service" 2>/dev/null | grep -q "$unit" &&
          printf '%s\t%s\t\t\t\t\n' "$label" "$(systemctl is-active --quiet "$unit" && echo true || echo false)"
      done
    fi
    if [ "$(uname -s)" = Darwin ]; then
      local xp=/Library/Apple/System/Library/CoreServices/XProtect.bundle
      [ -d "$xp" ] && printf 'Apple XProtect\ttrue\t\ttrue\t\t%s\n' "$(( (now - $(stat -f %m "$xp")) / 86400 ))"
    fi
  } | awk -F'\t' '
    function b(v) { return v == "true" ? "true" : v == "false" ? "false" : "null" }
    BEGIN { printf "[" }
    NF > 0 { gsub(/"/, "", $1); printf "%s{\"name\":\"%s\",\"enabled\":%s,\"upToDate\":%s,\"realTimeProtection\":%s,\"tamperProtection\":%s,\"signatureAgeDays\":%s}", (c++ ? "," : ""), $1, ($2 == "true" ? "true" : "false"), b($3), b($4), b($5), ($6 ~ /^[0-9]+$/ ? $6 : "null") }
    END { printf "]" }'
}

inv_firewall() {
  local on=false detail=""
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then on=true; detail="ufw"
  elif command -v systemctl >/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then on=true; detail="firewalld"
  elif command -v nft >/dev/null && nft list ruleset 2>/dev/null | grep -v bloody_isolation | grep -q "hook input"; then on=true; detail="nftables"
  elif command -v iptables >/dev/null && iptables -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)|^-A INPUT'; then on=true; detail="iptables"
  elif [ -x /usr/libexec/ApplicationFirewall/socketfilterfw ] && /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -qi enabled; then on=true; detail="macOS application firewall"
  fi
  printf '{"enabled":%s,"detail":%s}' "$on" "$( [ -n "$detail" ] && js "$detail" || echo null)"
}

# ---- Attack Reduction: hardening facts (graded by the platform; keys match contracts) ----------
fact_bool() { if "$@" >/dev/null 2>&1; then printf true; else printf false; fi; }
sshd_value() { # $1 = lower-case sshd option, $2 = OpenSSH default → effective value, or "none"
  command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ] || { printf none; return; }
  local v; v="$( (sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null) | awk -v k="$1" '$1 == k { print tolower($2); exit }')"
  if [ -z "$v" ] && [ -r /etc/ssh/sshd_config ]; then
    v="$(grep -iE "^[[:space:]]*$1[[:space:]]" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{ print tolower($2) }')"
  fi
  printf '%s' "${v:-$2}"
}
inv_hardening() {
  local out=""
  add() { out="${out:+$out,}\"$1\":$2"; }
  if [ "$(uname -s)" = Darwin ]; then
    add filevault_on "$(fact_bool sh -c 'fdesetup status | grep -q "FileVault is On"')"
    add gatekeeper_on "$(fact_bool sh -c 'spctl --status 2>&1 | grep -q "assessments enabled"')"
    add sip_on "$(fact_bool sh -c 'csrutil status | grep -q "enabled"')"
    local cu; cu="$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)"
    add auto_security_updates "$([ "$cu" = 0 ] && printf false || printf true)"
    add ssh_enabled "$(fact_bool launchctl list com.openssh.sshd)"
    add guest_enabled "$(fact_bool sh -c '[ "$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)" = 1 ]')"
  else
    add ssh_permit_root_login "$(js "$(sshd_value permitrootlogin prohibit-password)")"
    add ssh_password_auth "$(js "$(sshd_value passwordauthentication yes)")"
    [ -r /proc/sys/kernel/randomize_va_space ] && add aslr "$(tr -dc 0-9 < /proc/sys/kernel/randomize_va_space)"
    [ -r /etc/passwd ] && add uid0_accounts "$(js "$(awk -F: '$3 == 0 { print $1 }' /etc/passwd | paste -sd, -)")"
    if command -v apt-config >/dev/null 2>&1; then
      add auto_security_updates "$(fact_bool sh -c 'apt-config dump 2>/dev/null | grep -q "APT::Periodic::Unattended-Upgrade \"1\""')"
    elif command -v systemctl >/dev/null 2>&1 && { command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; }; then
      add auto_security_updates "$(fact_bool sh -c 'systemctl is-enabled dnf-automatic.timer || systemctl is-enabled dnf-automatic-install.timer || systemctl is-enabled yum-cron')"
    fi
  fi
  printf '{%s}' "$out"
}

inventory_json() {
  printf '{"software":%s,"services":%s,"users":%s,"processes":%s,"ports":%s,"antivirus":%s,"firewall":%s,"hardening":%s}' \
    "$(inv_software)" "$(inv_services)" "$(inv_users)" "$(inv_processes)" "$(inv_ports)" "$(inv_antivirus)" "$(inv_firewall)" "$(inv_hardening)"
}

send_inventory() {
  local f; f="$(mktemp)"; inventory_json > "$f"
  local pin=() l; while IFS= read -r l; do pin+=("$l"); done < <(curl_pin)
  curl -fsS --max-time 60 "${pin[@]}" -X POST "$PLATFORM_URL/api/v1/agent/inventory" \
    -H "authorization: Bearer $AGENT_TOKEN" -H "content-type: application/json" --data-binary "@$f"
  local rc=$?; rm -f "$f"; return $rc
}
INVENTORY_EVERY=1800

# ---- App Control -----------------------------------------------------------------------------
# Policy lines from GET /agent/app-control?format=lines (etag / mode / rule …). Core OS processes
# and the agent itself are never stopped (keep in sync with PROTECTED_PROGRAMS in contracts).
AC_POLICY="$STATE_DIR/app-control.policy"
AC_PROTECTED=" system smss.exe csrss.exe wininit.exe winlogon.exe services.exe lsass.exe lsaiso.exe svchost.exe explorer.exe dwm.exe fontdrvhost.exe conhost.exe powershell.exe sciatagent.exe msmpeng.exe registry init systemd systemd-journald systemd-logind systemd-udevd dbus-daemon sshd login agetty sudo bash sh dash curl nft launchd kernel_task loginwindow sciat-agent "
AC_PLATFORM=linux; [ "$(uname -s)" = Darwin ] && AC_PLATFORM=macos
AC_MODE=off AC_ETAG="" AC_LOADED=""
AC_RULES=()            # "action kind platform pattern ruleId"
# App Control enforcement reads /proc (Linux) and needs bash 4 associative arrays.
if [ "$AC_PLATFORM" = linux ] && [ "${BASH_VERSINFO[0]}" -ge 4 ]; then
  declare -A AC_SEEN=()  # pid:start → already reported
  declare -A AC_HASH=()  # path:mtime → sha256
  AC_SUPPORTED=1
else
  AC_SUPPORTED=0
fi

ac_sync() { # ac_sync <heartbeat response>: download the policy when its etag changed
  local etag; etag="$(printf '%s' "$1" | grep -o '"appControlEtag":"[0-9a-f]*"' | cut -d'"' -f4)"
  [ -n "$etag" ] || return 0
  [ -r "$AC_POLICY" ] && [ "$(head -1 "$AC_POLICY")" = "etag $etag" ] && return 0
  local pin=() l; while IFS= read -r l; do pin+=("$l"); done < <(curl_pin)
  local tmp; tmp="$(mktemp)"
  if curl -fsS --max-time 20 "${pin[@]}" "$PLATFORM_URL/api/v1/agent/app-control?format=lines" -H "authorization: Bearer $AGENT_TOKEN" -o "$tmp"; then
    mv "$tmp" "$AC_POLICY"; chmod 600 "$AC_POLICY"; log "app control policy updated ($etag)"
  else rm -f "$tmp"; fi
}

# Lower-case shell pattern from a rule value where only * is special.
ac_pattern() { local v="${1,,}"; v="${v//\\/\\\\}"; v="${v//\?/\\?}"; v="${v//\[/\\[}"; v="${v//\]/\\]}"; printf '%s' "$v"; }

ac_load() {
  [ "$AC_SUPPORTED" = 1 ] && [ -r "$AC_POLICY" ] || { AC_MODE=off; return; }
  local stamp; stamp="$(stat -c %Y "$AC_POLICY" 2>/dev/null || stat -f %m "$AC_POLICY")"
  [ "$stamp" = "$AC_LOADED" ] && return
  AC_LOADED="$stamp" AC_MODE=off AC_RULES=()
  local word id action kind platform value
  while read -r word id action kind platform value; do
    case "$word" in
      etag) AC_ETAG="$id" ;;
      mode) [[ "$id" =~ ^(off|audit|enforce)$ ]] && AC_MODE="$id" ;;
      rule)
        [[ "$platform" == any || "$platform" == "$AC_PLATFORM" ]] || continue
        [[ "$action" =~ ^(allow|block)$ && "$kind" =~ ^(name|path|sha256)$ ]] || continue
        AC_RULES+=("$action"$'\t'"$kind"$'\t'"$(ac_pattern "$value")"$'\t'"$id") ;;
    esac
  done < "$AC_POLICY"
}

ac_sha256() { # sets AC_SHA; cached by path + mtime (kept in this shell, not a subshell)
  local p="$1" m; m="$(stat -c %Y "$p" 2>/dev/null)" || { AC_SHA=""; return; }
  local k="$p:$m"
  [ -n "${AC_HASH[$k]:-}" ] || AC_HASH[$k]="$(sha256sum "$p" 2>/dev/null | awk '{print $1}')"
  AC_SHA="${AC_HASH[$k]}"
}

# Sets AC_VERDICT (allow|block|"") and AC_RULE for one program; allow beats block.
ac_decide() {
  local name="${1,,}" path="${2,,}" rawpath="$2" hashed=0 r action kind pat id
  AC_VERDICT="" AC_RULE=""
  for r in "${AC_RULES[@]}"; do
    IFS=$'\t' read -r action kind pat id <<< "$r"
    case "$kind" in
      name) [[ "$name" == $pat || "${path##*/}" == $pat ]] || continue ;;
      path) [[ -n "$path" && "$path" == $pat ]] || continue ;;
      sha256) [ "$hashed" = 1 ] || { ac_sha256 "$rawpath"; hashed=1; }; [ "$AC_SHA" = "$pat" ] || continue ;;
    esac
    if [ "$action" = allow ]; then AC_VERDICT=allow AC_RULE="$id"; return; fi
    [ -n "$AC_RULE" ] || { AC_VERDICT=block AC_RULE="$id"; }
  done
}

ac_tick() {
  [ "$AC_SUPPORTED" = 1 ] || return 0
  ac_load
  { [ "$AC_MODE" = off ] || [ ${#AC_RULES[@]} -eq 0 ]; } && return 0
  local events=() d pid exe name stat rest ppid gpp start verdict f
  for d in /proc/[0-9]*; do
    pid="${d#/proc/}"
    { [ "$pid" -le 2 ] || [ "$pid" = "$$" ]; } && continue
    exe="$(readlink "$d/exe" 2>/dev/null)" || continue      # kernel threads have no executable
    [ -n "$exe" ] || continue
    name="${exe##*/}"; name="${name% (deleted)}"
    [[ "$AC_PROTECTED" == *" ${name,,} "* ]] && continue
    # /proc/<pid>/stat: fields after "(comm) " are state, ppid, …; starttime is the 20th of them.
    stat="$(< "$d/stat")" 2>/dev/null || continue
    read -r -a f <<< "${stat##*) }"; ppid="${f[1]}" start="${f[19]}"
    # Never touch the agent's own helpers (curl, sha256sum… started by this script).
    gpp=""; [ -r "/proc/$ppid/stat" ] && { stat="$(< "/proc/$ppid/stat")"; read -r -a f <<< "${stat##*) }"; gpp="${f[1]}"; }
    { [ "$ppid" = "$$" ] || [ "$gpp" = "$$" ]; } && continue
    ac_decide "$name" "$exe"
    [ "$AC_VERDICT" = block ] || continue
    # Remembered per mode: a program audited earlier is still stopped once enforcement starts.
    [ -n "${AC_SEEN[$pid:$start:$AC_MODE]:-}" ] && continue
    AC_SEEN[$pid:$start:$AC_MODE]=1
    verdict=audited
    if [ "$AC_MODE" = enforce ] && kill -9 "$pid" 2>/dev/null; then verdict=blocked; fi
    log "app control: $verdict $exe (pid $pid, rule $AC_RULE)"
    events+=("{\"name\":$(js "$name"),\"path\":$(js "$exe"),\"ruleId\":$(js "$AC_RULE"),\"verdict\":\"$verdict\",\"occurredAt\":\"$(date -u +%FT%TZ)\"}")
  done
  [ ${#AC_SEEN[@]} -gt 5000 ] && AC_SEEN=()
  if [ ${#events[@]} -gt 0 ]; then
    local IFS=,
    api /agent/app-control/events "{\"events\":[${events[*]:0:200}]}" >/dev/null || log "could not report app control events"
  fi
  return 0
}

case "${1:-run}" in
  once) resp="$(checkin)" && { printf '%s\n' "$resp"; run_commands "$resp" || true; ac_sync "$resp"; ac_tick; send_inventory >/dev/null || log "inventory upload failed"; } ;;
  inventory) inventory_json; echo ;;
  status)
    echo "SCIAT Agent $AGENT_VERSION"
    echo "platform: $PLATFORM_URL"
    [ -r "$STATE_DIR/last-checkin" ] && echo "last check-in: $(cat "$STATE_DIR/last-checkin")" || echo "last check-in: never"
    ;;
  run)
    log "starting (version $AGENT_VERSION, platform $PLATFORM_URL)"
    delay=60 failures=0 last_inventory=0
    while true; do
      if resp="$(checkin 2>&1)"; then
        failures=0
        date -u +%FT%TZ > "$STATE_DIR/last-checkin" 2>/dev/null || true
        poll="$(printf '%s' "$resp" | grep -o '"pollSeconds":[0-9]*' | cut -d: -f2)"
        delay="${poll:-60}"
        # Ran a command: check in again soon so the platform sees the new state.
        if run_commands "$resp"; then delay=5; fi
        ac_sync "$resp"
        if [ $(( $(date +%s) - last_inventory )) -ge "$INVENTORY_EVERY" ]; then
          if send_inventory >/dev/null 2>&1; then last_inventory="$(date +%s)"; else log "inventory upload failed"; last_inventory=$(( $(date +%s) - INVENTORY_EVERY + 300 )); fi
        fi
      else
        failures=$((failures + 1))
        # Back off while the platform is unreachable (max 10 minutes), log every few attempts.
        delay=$(( 60 * (failures < 10 ? failures : 10) ))
        [ $((failures % 5)) -eq 1 ] && log "check-in failed ($failures in a row): ${resp:0:200}"
      fi
      # Sleep in 10-second slices, applying App Control between them.
      local_end=$(( $(date +%s) + delay ))
      while [ "$(date +%s)" -lt "$local_end" ]; do
        ac_tick
        rem=$(( local_end - $(date +%s) )); [ "$rem" -gt 10 ] && rem=10; [ "$rem" -lt 1 ] && rem=1
        sleep "$rem"
      done
    done
    ;;
  *) echo "usage: sciat-agent [run|once|status|inventory]" >&2; exit 2 ;;
esac
