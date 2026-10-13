#!/usr/bin/env bash
# Start the Bloody API and web UI together (Ctrl+C stops both).
# Run scripts/setup-local.sh once first.
set -euo pipefail
cd "$(dirname "$0")/.."

pnpm dev:api &
API_PID=$!
trap 'kill $API_PID 2>/dev/null || true' EXIT INT TERM

echo "Waiting for the API on :4000 ..."
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:4000/api/v1/healthz >/dev/null 2>&1; then echo "API is up."; break; fi
  if ! kill -0 "$API_PID" 2>/dev/null; then echo "API failed to start — see the log above." >&2; exit 1; fi
  sleep 1
done

# --host makes the UI reachable on the server IP (http://<server-ip>:5173), not just localhost.
pnpm dev:web --host "${BLOODY_WEB_HOST:-0.0.0.0}"
