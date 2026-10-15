# Shared helpers for the Bloody install/start/doctor scripts (sourced, not executed).

# The address other machines reach this server on: the source address of the default route
# (not "the first IP", which may be a Docker or VPN bridge).
bloody_detect_ip() {
  local ip=""
  if command -v ip >/dev/null; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -nE 's/.* src ([0-9.]+).*/\1/p' | head -1)"
  fi
  [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9.]+$' | grep -vE '^(127\.|172\.(1[7-9]|2[0-9]|3[01])\.)' | head -1)"
  echo "${ip:-127.0.0.1}"
}

# 0 when the IPv4 address is private / not internet-routable (LAN, CGNAT/Tailscale, link-local).
bloody_is_private_ip() {
  case "$1" in
    10.*|192.168.*|127.*|169.254.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
    *) return 1 ;;
  esac
}

# 0 when this machine looks like a cloud VM (a VPS often has a private address behind NAT).
bloody_is_cloud_vm() {
  local vendor
  vendor="$(cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name /sys/class/dmi/id/bios_vendor 2>/dev/null | tr '\n' ' ')"
  echo "$vendor" | grep -qiE 'amazon|ec2|google|digitalocean|hetzner|linode|akamai|vultr|ovh|scaleway|upcloud|oracle|microsoft corporation|alibaba|contabo|ionos' && return 0
  [ -f /etc/cloud/cloud.cfg ] && [ -d /var/lib/cloud/instance ] && return 0
  return 1
}

bloody_env_get() { if [ -f .env ]; then grep -E "^$1=" .env | tail -1 | cut -d= -f2- || true; fi; }

# Set KEY=VALUE in .env (replace in place, or append).
bloody_env_set() {
  local key="$1" value="$2" tmp
  if grep -qE "^${key}=" .env 2>/dev/null; then
    tmp="$(mktemp)"
    awk -v k="$key" -v v="$value" 'BEGIN { FS = OFS = "=" } $1 == k { print k "=" v; next } { print }' .env > "$tmp" && cat "$tmp" > .env && rm -f "$tmp"
  else
    echo "${key}=${value}" >> .env
  fi
}

# In "auto" address mode (LAN installs), point PUBLIC_URL / CORS_ORIGINS at the current address.
# Returns 0 when the address changed.
bloody_refresh_address() {
  [ "$(bloody_env_get BLOODY_ADDRESS_MODE)" = auto ] || return 1
  local ip port url
  ip="$(bloody_detect_ip)"
  port="$(bloody_env_get BLOODY_WEB_PORT)"; port="${port:-5173}"
  url="http://${ip}:${port}"
  [ "$(bloody_env_get PUBLIC_URL)" = "$url" ] && return 1
  bloody_env_set PUBLIC_URL "$url"
  bloody_env_set CORS_ORIGINS "${url},http://localhost:${port}"
  return 0
}
