#!/usr/bin/env bash
# Start the Bloody API and web UI together (Ctrl+C stops both).
# Run ./install.sh once first (it can also install this as the `bloody` service).
#
#   bash scripts/start-demo.sh           # start
#   bash scripts/start-demo.sh --fresh   # first re-anchor the demo data at "now" (agents check in,
#                                        # incidents are recent) — use this before showing it to someone
#   bash scripts/start-demo.sh --prod    # serve an optimized production build of the UI (faster, no
#                                        # dev-server live reload); options can be combined
set -euo pipefail
cd "$(dirname "$0")/.."
# Background runs (install.sh without systemd) record this process (the group leader) to stop it later.
if [ -n "${BLOODY_PIDFILE:-}" ]; then echo $$ > "$BLOODY_PIDFILE"; fi

FRESH=0; PROD=0
for arg in "$@"; do
  case "$arg" in
    --fresh) FRESH=1 ;;
    --prod) PROD=1 ;;
    *) echo "unknown option: $arg (use --fresh and/or --prod)" >&2; exit 2 ;;
  esac
done

. scripts/lib.sh
# LAN installs follow the server's current address (links in e-mails and reports use PUBLIC_URL).
if bloody_refresh_address; then echo "Server address is now $(bloody_env_get PUBLIC_URL)"; fi
# Where the UI listens: .env decides (public installs: 127.0.0.1 behind HTTPS; LAN: every interface).
BLOODY_WEB_HOST="${BLOODY_WEB_HOST:-$(bloody_env_get BLOODY_WEB_HOST)}"

# Pick up new dependencies and database migrations after a `git pull` (both are no-ops when current).
pnpm install --frozen-lockfile --prefer-offline >/dev/null
echo "Applying database migrations ..."
pnpm db:migrate

if [ "$FRESH" = 1 ]; then
  echo "Refreshing demo data to the current time ..."
  pnpm --filter @bloody/api seed:dev --refresh
fi
if [ "$PROD" = 1 ]; then
  echo "Building the production UI ..."
  pnpm --filter @bloody/web exec vite build
fi

if [ "$PROD" = 1 ]; then
  pnpm --filter @bloody/api exec tsx src/server.ts &   # no file watching
else
  pnpm dev:api &
fi
API_PID=$!
trap 'kill $API_PID 2>/dev/null || true' EXIT INT TERM

echo "Waiting for the API on :4000 ..."
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:4000/api/v1/healthz >/dev/null 2>&1; then echo "API is up."; break; fi
  if ! kill -0 "$API_PID" 2>/dev/null; then echo "API failed to start — see the log above." >&2; exit 1; fi
  sleep 1
done

# --host makes the UI reachable on the server IP (http://<server-ip>:5173), not just localhost.
# The UI proxies /api to the API on this same machine.
export BLOODY_API_URL="http://127.0.0.1:${PORT_API:-4000}"
if [ "$PROD" = 1 ]; then
  pnpm --filter @bloody/web exec vite preview --host "${BLOODY_WEB_HOST:-0.0.0.0}" --port 5173 --strictPort
else
  pnpm dev:web --host "${BLOODY_WEB_HOST:-0.0.0.0}"
fi
