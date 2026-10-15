import { describe, expect, it } from "vitest";
import { EngineClient } from "../http/client.js";
import { mockFetch, testResolver } from "../test-support/http.js";
import { buildIsolationPolicy, isIpOrCidr, isolationBlockRanges, isolationScriptArgs } from "./isolation.js";
import { createWazuhActiveResponse } from "./wazuh.js";

const req = (parameters: Record<string, unknown>) => ({ parameters });

describe("isolation block ranges (Windows Firewall)", () => {
  it("LAN mode blocks local networks minus the management and DNS addresses", () => {
    const r = isolationBlockRanges({ mode: "lan", allow: ["192.168.1.10"], dns: ["192.168.1.1"] });
    expect(r.v4).toEqual([
      "10.0.0.0-10.255.255.255",
      "172.16.0.0-172.31.255.255",
      "192.168.0.0-192.168.1.0",
      "192.168.1.2-192.168.1.9",
      "192.168.1.11-192.168.255.255",
      "100.64.0.0-100.127.255.255",
      "169.254.0.0-169.254.255.255",
    ]);
    expect(r.v4.some((x) => x.startsWith("8.") || x.startsWith("1."))).toBe(false); // internet untouched
    expect(r.v6).toEqual(["fc00:0:0:0:0:0:0:0-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80:0:0:0:0:0:0:0-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]);
  });

  it("full mode blocks everything except management, loopback and DHCP broadcast", () => {
    const r = isolationBlockRanges({ mode: "full", allow: ["203.0.113.10", "2001:db8::/32"], dns: [] });
    expect(r.v4).toEqual(["0.0.0.1-126.255.255.255", "128.0.0.0-203.0.113.9", "203.0.113.11-255.255.255.254"]);
    expect(r.v6).toEqual([
      "0:0:0:0:0:0:0:0",
      "0:0:0:0:0:0:0:2-2001:db7:ffff:ffff:ffff:ffff:ffff:ffff",
      "2001:db9:0:0:0:0:0:0-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ]);
  });
});

describe("isolation policy", () => {
  it("validates IPs and CIDRs strictly (no hostnames reach endpoint firewalls)", () => {
    for (const ok of ["10.0.0.5", "203.0.113.0/24", "2001:db8::1", "2001:db8::/32"]) expect(isIpOrCidr(ok)).toBe(true);
    for (const bad of ["bloody.example", "10.0.0.5/40", "10.0.0.0/4", "1.2.3.4; rm -rf /", "", "10.0.0.5/24/1"]) expect(isIpOrCidr(bad)).toBe(false);
  });

  it("defaults to full isolation and always keeps the management path", () => {
    const p = buildIsolationPolicy(req({}), ["10.0.0.5", "203.0.113.10"]);
    expect(p).toEqual({ mode: "full", allow: ["10.0.0.5", "203.0.113.10"], dns: [] });
    expect(isolationScriptArgs(p).slice(0, 3)).toEqual(["isolate", "full", "allow=10.0.0.5,203.0.113.10"]);
  });

  it("supports LAN isolation that keeps internet, merging extra allow entries", () => {
    const p = buildIsolationPolicy(req({ mode: "lan", allow: ["192.168.1.1"], dns: "1.1.1.1" }), ["10.0.0.5"]);
    expect(isolationScriptArgs(p).slice(0, 4)).toEqual(["isolate", "lan", "allow=10.0.0.5,192.168.1.1", "dns=1.1.1.1"]);
  });

  it("refuses isolation that could never be released (no management addresses) and bad input", () => {
    expect(() => buildIsolationPolicy(req({ mode: "lan" }), [])).toThrow(/released later/);
    expect(() => buildIsolationPolicy(req({ mode: "partial" }), ["10.0.0.5"])).toThrow(/mode/);
    expect(() => buildIsolationPolicy(req({ allow: ["evil.example"] }), ["10.0.0.5"])).toThrow(/not an IP/);
    expect(isolationScriptArgs("release")).toEqual(["release"]);
  });

  it("Wazuh sends bloody-isolate with the mode and allow-list, and release reverses it", async () => {
    const ar = createWazuhActiveResponse({ isolationAllow: ["10.0.0.5"] });
    expect(ar.supported).toEqual(expect.arrayContaining(["isolate_endpoint", "release_endpoint"]));
    const { fetch, calls } = mockFetch([{ method: "PUT", path: "/active-response", json: { data: { affected_items: ["003"], failed_items: [] }, error: 0 } }]);
    const client = new EngineClient({ engine: "wazuh", baseUrl: "https://wazuh.acme.example", fetch, resolveHost: testResolver });
    const base = { actionId: "11111111-1111-4111-8111-111111111111", tenantId: "22222222-2222-4222-8222-222222222222", organizationId: "33333333-3333-4333-8333-333333333333", requestedBy: "user:a", requestedVia: "user", approvedBy: "user:b", reason: "lateral movement" };
    const iso = await ar.execute({ ...base, action: "isolate_endpoint", target: { kind: "asset", id: "003" }, parameters: { mode: "lan", agents: ["003"] } } as never, { client, clock: () => new Date() } as never);
    expect(iso.status).toBe("succeeded");
    const sent = JSON.parse(calls[0]!.body ?? "{}");
    expect(sent.command).toBe("!bloody-isolate");
    expect(sent.arguments.slice(0, 3)).toEqual(["isolate", "lan", "allow=10.0.0.5"]);
    expect(sent.arguments[3]).toMatch(/^block4=10\.0\.0\.0-10\.0\.0\.4,10\.0\.0\.6-10\.255\.255\.255,/);
    expect(iso.reversal).toEqual({ action: "release_endpoint", parameters: { agents: ["003"] } });
    await ar.execute({ ...base, action: "release_endpoint", target: { kind: "asset", id: "003" }, parameters: { agents: ["003"] } } as never, { client, clock: () => new Date() } as never);
    expect(JSON.parse(calls[1]!.body ?? "{}")).toMatchObject({ command: "!bloody-isolate", arguments: ["release"] });
  });
});
