#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-SCIAT-Proprietary
// Copyright (c) 2026 SCIAT AFRICA. All rights reserved.
//
// SCIAT Agent load test: enrolls N simulated agents, then each checks in on the real schedule
// (heartbeat every --interval seconds, with jitter) and uploads one realistic host inventory.
// Reports latency percentiles and errors per endpoint. No dependencies (Node 18+).
//
//   node scripts/agent-loadtest.mjs --url http://127.0.0.1:4100 --account-key sak_… --org-key acme \
//        --agents 500 --minutes 3 [--interval 60] [--ids-out agents.txt]
//
// Run it only against a platform you operate: it creates real agents (remove them afterwards,
// e.g. with the ids written by --ids-out).

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith("--") ? [...acc, [a.slice(2), all[i + 1] && !all[i + 1].startsWith("--") ? all[i + 1] : "true"]] : acc), []),
);
const URL_ = (args.url ?? "http://127.0.0.1:4100").replace(/\/+$/, "");
const AGENTS = Number(args.agents ?? 100);
const MINUTES = Number(args.minutes ?? 2);
const INTERVAL = Number(args.interval ?? 60);
const PREFIX = args.prefix ?? `lt-${Date.now().toString(36)}`;
if (!args["account-key"] || !args["org-key"]) {
  console.error("usage: --account-key sak_… --org-key <organization key> [--agents N] [--minutes M]");
  process.exit(2);
}

const stats = new Map();
const record = (name, ms, status) => {
  const s = stats.get(name) ?? { lat: [], status: new Map() };
  s.lat.push(ms);
  s.status.set(status, (s.status.get(status) ?? 0) + 1);
  stats.set(name, s);
};
async function call(name, path, body, token) {
  const t0 = performance.now();
  let status = 0;
  let json = null;
  try {
    const res = await fetch(`${URL_}/api/v1${path}`, { method: "POST", headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });
    status = res.status;
    json = await res.json().catch(() => null);
  } catch {
    status = "network";
  }
  record(name, performance.now() - t0, status);
  return { status, json };
}

const pick = (n, f) => Array.from({ length: n }, (_, i) => f(i));
function inventory(i) {
  return {
    software: pick(300, (k) => ({ name: `package-${k}`, version: `1.${k % 17}.${i % 9}`, publisher: k % 3 ? "Vendor Ltd" : null })),
    services: pick(180, (k) => ({ name: `svc${k}`, displayName: `Service ${k}`, state: k % 4 ? "running" : "stopped", startMode: "auto", account: "LocalSystem" })),
    users: pick(6, (k) => ({ name: `user${k}`, admin: k === 0, enabled: true, loggedIn: k === 1 })),
    processes: pick(150, (k) => ({ pid: 1000 + k, name: `proc${k}.exe`, path: `C:\\Program Files\\App${k % 20}\\proc${k}.exe`, user: "SYSTEM" })),
    ports: pick(12, (k) => ({ protocol: "tcp", address: "0.0.0.0", port: 1000 + k, process: `proc${k}.exe` })),
    antivirus: [{ name: "Microsoft Defender Antivirus", enabled: true, upToDate: true, realTimeProtection: true, tamperProtection: true, signatureAgeDays: 0 }],
    firewall: { enabled: true, detail: null },
    hardening: { smb1_enabled: false, llmnr_disabled: true, lsa_run_as_ppl: 1, uac_enabled: true },
    autoruns: pick(120, (k) => ({ kind: k % 3 ? "service" : "run_key", location: `HKLM\\Software\\Run${k % 5}`, name: `entry${k}`, command: `C:\\Program Files\\App${k % 20}\\entry${k}.exe --start`, signed: true })),
    patches: { source: "windows_update", pending: pick(4, (k) => ({ title: `Update ${k}`, id: `KB50${i % 10}${k}`, security: k < 2, severity: k === 0 ? "important" : null })), rebootRequired: false, lastCheckedAt: new Date().toISOString() },
  };
}

const pct = (arr, p) => {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
};
function report(title) {
  console.log(`\n${title}`);
  console.log("endpoint            requests   p50 ms   p95 ms   p99 ms   max ms   statuses");
  for (const [name, s] of stats) {
    const statuses = [...s.status].map(([k, v]) => `${k}×${v}`).join(" ");
    console.log(`${name.padEnd(18)} ${String(s.lat.length).padStart(9)} ${pct(s.lat, 50).toFixed(0).padStart(8)} ${pct(s.lat, 95).toFixed(0).padStart(8)} ${pct(s.lat, 99).toFixed(0).padStart(8)} ${Math.max(...s.lat).toFixed(0).padStart(8)}   ${statuses}`);
  }
}

// 1. Enroll (20 at a time, like a mass deployment through an RMM).
const agents = [];
const queue = pick(AGENTS, (i) => i);
await Promise.all(
  pick(20, async () => {
    for (let i = queue.shift(); i !== undefined; i = queue.shift()) {
      // Like the installers: a busy platform (429) is retried after a pause.
      let r = { status: 429 };
      for (let attempt = 1; attempt <= 8 && r.status === 429; attempt++) {
        if (attempt > 1) await new Promise((res) => setTimeout(res, 5000 + Math.random() * 5000));
        r = await call("enroll", "/agent/enroll", { accountKey: args["account-key"], organizationKey: args["org-key"], hostname: `${PREFIX}-${i}`, platform: "windows", os: "Microsoft Windows 11 Pro 10.0.26200", version: "1.5.0", ips: [`10.20.${Math.floor(i / 250)}.${(i % 250) + 1}`] });
      }
      if (r.status === 200 && r.json?.token) agents.push({ i, token: r.json.token, id: r.json.agentId });
    }
  }),
);
report(`Enrolled ${agents.length} of ${AGENTS} agents`);
if (args["ids-out"]) (await import("node:fs")).writeFileSync(args["ids-out"], agents.map((a) => a.id).join("\n") + "\n");
stats.clear();

// 2. Steady state: heartbeat every INTERVAL s (jittered), one inventory per agent in the first interval.
const until = Date.now() + MINUTES * 60_000;
const t0 = Date.now();
await Promise.all(
  agents.map(async (a) => {
    await new Promise((r) => setTimeout(r, Math.random() * INTERVAL * 1000));
    let inventoryDone = false;
    while (Date.now() < until) {
      await call("heartbeat", "/agent/heartbeat", { hostname: `${PREFIX}-${a.i}`, os: "Microsoft Windows 11 Pro 10.0.26200", version: "1.5.0", ips: [`10.20.${Math.floor(a.i / 250)}.${(a.i % 250) + 1}`], uptimeSeconds: 3600, isolation: { state: "not_isolated" }, engines: {}, platformIps: ["127.0.0.1"], dnsServers: ["10.0.0.53"] }, a.token);
      if (!inventoryDone) {
        await call("inventory", "/agent/inventory", inventory(a.i), a.token);
        inventoryDone = true;
      }
      await new Promise((r) => setTimeout(r, INTERVAL * 1000 * (0.9 + Math.random() * 0.2)));
    }
  }),
);
const secs = (Date.now() - t0) / 1000;
const total = [...stats.values()].reduce((n, s) => n + s.lat.length, 0);
report(`${agents.length} agents for ${secs.toFixed(0)} s — ${(total / secs).toFixed(1)} requests/s`);
