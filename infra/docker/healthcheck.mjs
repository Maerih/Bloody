// SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
// Copyright (c) 2026 Bloody. All rights reserved.
//
// Container liveness probe for the distroless API image (no shell, no curl):
//   node /app/healthcheck.mjs [path]
// Exits 0 when GET http://127.0.0.1:$PORT<path> answers 2xx within the timeout.
const port = Number.parseInt(process.env.PORT ?? "4000", 10);
const path = process.argv[2] ?? process.env.HEALTHCHECK_PATH ?? "/api/v1/healthz";
const timeoutMs = Number.parseInt(process.env.HEALTHCHECK_TIMEOUT_MS ?? "3000", 10);

try {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: { "user-agent": "bloody-healthcheck" },
  });
  if (res.status >= 200 && res.status < 300) process.exit(0);
  console.error(`healthcheck: ${path} returned ${res.status}`);
} catch (err) {
  console.error(`healthcheck: ${path} unreachable: ${err instanceof Error ? err.message : String(err)}`);
}
process.exit(1);
