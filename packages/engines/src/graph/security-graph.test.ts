import { describe, expect, it } from "vitest";
import { BufferingSink } from "../notifications.js";
import { makeEvent, ORG_1, ORG_2, TENANT_A, TENANT_B } from "../test-support/fixtures.js";
import { ManualClock } from "../util/clock.js";
import { InMemoryGraphStore } from "./memory-store.js";
import { SecurityGraph } from "./security-graph.js";
import { GraphError } from "./types.js";

const HASH = "a".repeat(64);

function graph(opts: { cache?: number } = {}) {
  const store = new InMemoryGraphStore({ tenantId: TENANT_A });
  const sink = new BufferingSink();
  const g = new SecurityGraph({ store, sink, clock: new ManualClock("2026-03-01T12:00:00Z"), resolutionCacheSize: opts.cache ?? 10_000 });
  return { store, g, sink };
}

const officeChain = () =>
  makeEvent({
    category: "process",
    eventType: "process_start",
    asset: { hostname: "WS-042.corp.local", agentId: "AG-1", ip: ["10.0.0.42"], os: "Windows 11" },
    user: { name: "bob", domain: "CORP" },
    process: {
      pid: 4242,
      name: "powershell.exe",
      path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      commandLine: "powershell -enc AAAA",
      user: "CORP\\bob",
      hashSha256: HASH,
      parent: { pid: 100, path: "C:\\Program Files\\Microsoft Office\\WINWORD.EXE" },
    },
    network: { dstIp: "198.51.100.23", dstPort: 443, httpHost: "evil.example", httpUrl: "https://evil.example/payload" },
    indicators: [{ type: "ip", value: "198.51.100.23" }],
    attack: [{ id: "T1059.001", name: "PowerShell", tactic: "execution" }],
  });

describe("SecurityGraph.ingestEvent — entity resolution", () => {
  it("builds endpoint, user, process tree, file, hash, network, indicator and technique entities", async () => {
    const { g, store } = graph();
    const r = await g.ingestEvent(officeChain());
    const keys = r.entities.map((e) => `${e.kind}:${e.key}`);
    expect(keys).toEqual(
      expect.arrayContaining([
        "endpoint:ws-042",
        "user:corp\\bob",
        "process:ws-042|4242|c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
        "file:ws-042|c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
        `hash:${HASH}`,
        "ip:198.51.100.23",
        "domain:evil.example",
        "url:https://evil.example/payload",
        "indicator:ip:198.51.100.23",
        "technique:T1059.001",
      ]),
    );
    const kinds = (k: string) => r.edges.filter((e) => e.kind === k).length;
    expect(kinds("runs_on")).toBe(2); // process + parent
    expect(kinds("spawned")).toBe(1);
    expect(kinds("executed")).toBe(1);
    expect(kinds("has_hash")).toBe(1);
    expect(kinds("authenticates_as")).toBe(1); // process runs as user
    expect(kinds("logged_into")).toBe(1);
    expect(kinds("resolves_to")).toBe(1);
    expect(kinds("indicates")).toBe(1);
    expect(kinds("observed_on")).toBe(4); // indicator + technique, each on the endpoint and the acting user
    const tech = await store.findNodes({ kind: "technique" });
    expect(tech[0]!.organizationId).toBeNull();
    // idempotent: re-ingesting creates nothing new and bumps observation counters
    const before = store.size;
    await g.ingestEvent(officeChain());
    expect(store.size).toEqual(before);
    const host = (await store.findNodes({ kind: "endpoint" }))[0]!;
    expect(host.props.seenCount).toBe(2);
  });

  it("resolves the same asset across events carrying different identifiers (without cache)", async () => {
    const { g, store } = graph({ cache: 0 });
    await g.ingestEvent(makeEvent({ asset: { agentId: "AG-7" }, category: "process", process: { name: "a.exe", pid: 1 } }));
    await g.ingestEvent(makeEvent({ asset: { agentId: "ag-7", hostname: "SRV-7" }, category: "process", process: { name: "b.exe", pid: 2 } }));
    await g.ingestEvent(makeEvent({ asset: { hostname: "srv-7.corp.example" }, category: "process", process: { name: "c.exe", pid: 3 } }));
    const hosts = await store.findNodes({ kind: "endpoint" });
    expect(hosts).toHaveLength(1);
    expect(hosts[0]!.key).toBe("agent:ag-7");
    expect(hosts[0]!.props).toMatchObject({ agentId: "ag-7", hostname: "srv-7.corp.example", hostKey: "srv-7" });
    expect(await store.countNodes({ kind: "process" })).toBe(3);
  });

  it("models authentication: success links identity and source, failure records the attempt", async () => {
    const { g, store } = graph();
    await g.ingestEvent(
      makeEvent({
        category: "authentication",
        outcome: "success",
        source: { kind: "identity", product: "entra-id" },
        asset: { hostname: "vpn-gw" },
        identity: { provider: "entra-id", principal: "Bob@Corp.example", sourceIp: "203.0.113.9", geo: { country: "FR" } },
      }),
    );
    await g.ingestEvent(makeEvent({ category: "authentication", outcome: "failure", asset: { hostname: "vpn-gw" }, identity: { provider: "entra-id", principal: "eve@corp.example", sourceIp: "203.0.113.66" } }));
    const id = await store.getNodeByKey(ORG_1, "identity", "entra-id:bob@corp.example");
    expect(id).not.toBeNull();
    const out = await store.edgesOf([id!.id], { direction: "both" });
    expect(out.map((e) => e.kind).sort()).toEqual(["authenticates_as", "logged_into"]);
    const failedIp = await store.getNodeByKey(ORG_1, "ip", "203.0.113.66");
    const failEdges = await store.edgesOf([failedIp!.id], { direction: "out" });
    expect(failEdges).toHaveLength(1);
    expect(failEdges[0]!.kind).toBe("connected_to");
    expect(failEdges[0]!.props.authFailure).toBe(true);
  });

  it("rejects events of another tenant and invalid events", async () => {
    const { g } = graph();
    await expect(g.ingestEvent(makeEvent({ tenantId: TENANT_B }))).rejects.toMatchObject({ code: "tenant_mismatch" });
    await expect(g.ingestEvent({ ...makeEvent(), category: "bogus" } as never)).rejects.toThrow();
  });
});

describe("SecurityGraph relationship queries", () => {
  async function identityEstate() {
    const ctx = graph();
    const { g } = ctx;
    const bob = await g.ingestIdentity({ organizationId: ORG_1, provider: "entra-id", principal: "bob@corp.example", privileged: true, mfaEnabled: false });
    const svc = await g.ingestIdentity({ organizationId: ORG_1, provider: "ad", principal: "svc-backup", kind: "service_account", privileged: false });
    const admins = await g.ingestIdentity({ organizationId: ORG_1, provider: "ad", principal: "Domain Admins", kind: "group" });
    const dc = await g.ingestAsset({ organizationId: ORG_1, name: "DC-01", hostname: "dc-01", kind: "domain_controller", criticality: "crown_jewel" });
    const db = await g.ingestAsset({ organizationId: ORG_1, name: "DB-01", hostname: "db-01", kind: "database", criticality: "high" });
    await g.relate(bob.id, "member_of", admins.id);
    await g.relate(admins.id, "admin_of", dc.id);
    await g.relate(bob.id, "admin_of", db.id);
    await g.relate(svc.id, "has_access_to", db.id);
    // OS account of bob, linked to the IdP identity, logs into a workstation and runs a process on another
    await g.ingestEvent(makeEvent({ category: "authentication", outcome: "success", asset: { hostname: "ws-1" }, user: { name: "bob", domain: "CORP" }, identity: { provider: "entra-id", principal: "bob@corp.example" } }));
    await g.ingestEvent(makeEvent({ category: "process", asset: { hostname: "ws-2" }, process: { pid: 7, name: "excel.exe", user: "CORP\\bob" } }));
    return { ...ctx, bob, svc, admins, dc, db };
  }

  it("assetsForIdentity follows direct rights, group rights, linked accounts and process ownership", async () => {
    const { g, bob } = await identityEstate();
    const assets = await g.assetsForIdentity(bob.id);
    const byKey = Object.fromEntries(assets.map((a) => [a.node.key, a.relations]));
    expect(byKey["db-01"]).toEqual(["admin_of"]);
    expect(byKey["dc-01"]).toEqual(["admin_of via group Domain Admins"]);
    expect(byKey["ws-1"]).toEqual(expect.arrayContaining(["logged_into"]));
    expect(byKey["ws-2"]).toEqual(["logged_into via linked account CORP\\bob", "ran processes on"]);
    expect(assets[0]!.relations[0]).toMatch(/^admin_of/); // strongest relationship first
  });

  it("identitiesReaching expands groups and linked accounts, privileged first", async () => {
    const { g, dc, db } = await identityEstate();
    const toDc = await g.identitiesReaching(dc.id);
    const labels = toDc.map((r) => `${r.node.kind}:${r.node.label}:${r.relations[0]}`);
    expect(labels[0]).toBe("identity:bob@corp.example:admin_of via group Domain Admins");
    expect(labels).toEqual(expect.arrayContaining(["group:Domain Admins:admin_of"]));
    expect(toDc.find((r) => r.node.kind === "user")?.relations[0]).toMatch(/linked account/);
    // natural-key refs resolve across asset kinds (the database was inventoried as a data_store)
    const toDb = await g.identitiesReaching({ organizationId: ORG_1, kind: "server", key: "db-01" });
    expect(toDb).toEqual(await g.identitiesReaching(db.id));
    expect(toDb.map((r) => r.node.label)).toEqual(expect.arrayContaining(["bob@corp.example", "svc-backup"]));
  });

  it("whereObserved / orgsAffectedByIndicator span telemetry and organizations", async () => {
    const { g } = graph();
    await g.ingestEvent(officeChain());
    await g.ingestEvent(makeEvent({ organizationId: ORG_2, category: "network", asset: { hostname: "hr-07" }, network: { dstIp: "198.51.100.23", dstPort: 443 } }));
    const all = await g.whereObserved({ type: "ip", value: "198.51.100.23" });
    expect(all.map((o) => `${o.organizationId}:${o.node.key}`).sort()).toEqual([`${ORG_1}:corp\\bob`, `${ORG_1}:ws-042`, `${ORG_2}:hr-07`].sort());
    const ws = all.find((o) => o.node.key === "ws-042")!;
    expect(ws.via).toEqual(expect.arrayContaining(["indicator match"]));
    expect(ws.via.some((v) => v.startsWith("process powershell.exe connected to"))).toBe(true);
    const org1Only = await g.whereObserved({ type: "ip", value: "198.51.100.23" }, { organizationId: ORG_1 });
    expect(org1Only.every((o) => o.organizationId === ORG_1)).toBe(true);
    const orgs = await g.orgsAffectedByIndicator("ip", "198.51.100.23");
    expect(orgs.map((o) => o.organizationId).sort()).toEqual([ORG_1, ORG_2].sort());
    expect(orgs.find((o) => o.organizationId === ORG_1)).toMatchObject({ assets: 1, identities: 1 });
    // hash observed through a file on a host
    const viaHash = await g.whereObserved({ type: "sha256", value: HASH.toUpperCase() });
    expect(viaHash.map((o) => o.node.key)).toEqual(["ws-042"]);
    await expect(g.whereObserved({ type: "ip", value: "nope" })).rejects.toBeInstanceOf(GraphError);
  });

  it("actorsForInfrastructure links observables to actors via intel indicators", async () => {
    const { g, store } = graph();
    await g.ingestIndicator({ organizationId: ORG_1, type: "ip", value: "198.51.100.23", confidence: 90, severity: "critical", source: "misp", threatActor: "TA-Example", malware: "LoaderX" });
    await g.ingestEvent(officeChain());
    const ip = await store.getNodeByKey(ORG_1, "ip", "198.51.100.23");
    const actors = await g.actorsForInfrastructure(ip!.id);
    expect(actors.map((a) => `${a.node.kind}:${a.node.label}`)).toEqual(["malware:LoaderX", "threat_actor:TA-Example"]);
    await expect(g.ingestIndicator({ organizationId: ORG_1, type: "domain", value: "bad value with spaces" })).rejects.toThrow();
  });

  it("blastRadius follows attacker movement; exploitability gating is optional", async () => {
    const { g } = graph();
    const ws = await g.ingestAsset({ organizationId: ORG_1, name: "WS-1", hostname: "ws-1", criticality: "medium" });
    const srv = await g.ingestAsset({ organizationId: ORG_1, name: "SRV-2", hostname: "srv-2", kind: "server", criticality: "medium" });
    const dc = await g.ingestAsset({ organizationId: ORG_1, name: "DC-1", hostname: "dc-1", kind: "server", criticality: "high" });
    const vault = await g.ingestAsset({ organizationId: ORG_1, name: "Payments DB", hostname: "pay-db", kind: "database", criticality: "crown_jewel" });
    const admin = await g.ingestIdentity({ organizationId: ORG_1, provider: "ad", principal: "da-admin", privileged: true });
    await g.relate(admin.id, "logged_into", ws.id); // cached admin session on the workstation
    await g.relate(admin.id, "admin_of", dc.id);
    await g.relate(dc.id, "contains", vault.id);
    await g.relate(ws.id, "can_reach", srv.id);

    const worst = await g.blastRadius(ws.id, 3);
    expect(worst.nodes.map((n) => n.node.key).sort()).toEqual(["ad:da-admin", "dc-1", "pay-db", "srv-2"].sort());
    expect(worst.byKind).toMatchObject({ identity: 1, server: 2, data_store: 1 });
    expect(worst.crownJewels.map((n) => n.key)).toEqual(["pay-db"]);
    expect(worst.privilegedIdentities).toBe(1);
    expect(worst.nodes.find((n) => n.node.key === "ad:da-admin")!.via).toMatch(/Credential Dumping/);

    const gated = await g.blastRadius(ws.id, 3, { assumeExploitable: false });
    expect(gated.nodes.map((n) => n.node.key)).not.toContain("srv-2");
    const shallow = await g.blastRadius(ws.id, 1);
    expect(shallow.nodes.map((n) => n.node.key).sort()).toEqual(["ad:da-admin", "srv-2"]);
  });

  it("incidentsSharing finds shared indicators / infrastructure / techniques with weighted ranking", async () => {
    const { g } = graph();
    const ind = { type: "ip" as const, value: "198.51.100.23" };
    const ep = { kind: "endpoint" as const, key: "ws-042", label: "WS-042" };
    await g.linkIncident({ incidentId: "10000000-0000-4000-8000-000000000001", organizationId: ORG_1, title: "I1", entities: [ep], indicators: [ind], techniques: [{ id: "T1059.001" }] });
    await g.linkIncident({ incidentId: "10000000-0000-4000-8000-000000000002", organizationId: ORG_1, title: "I2", indicators: [ind] });
    await g.linkIncident({ incidentId: "10000000-0000-4000-8000-000000000003", organizationId: ORG_1, title: "I3", techniques: [{ id: "T1059.001" }] });
    await g.linkIncident({ incidentId: "10000000-0000-4000-8000-000000000004", organizationId: ORG_2, title: "I4 other customer", indicators: [ind], techniques: [{ id: "T1059.001" }] });
    await g.linkIncident({ incidentId: "10000000-0000-4000-8000-000000000005", organizationId: ORG_1, title: "I5", entities: [ep], malware: ["LoaderX"] });

    const org = await g.incidentsSharing("10000000-0000-4000-8000-000000000001");
    expect(org.map((s) => s.incident.label)).toEqual(["I2", "I5", "I3"]);
    expect(org[0]!.shared[0]).toMatchObject({ category: "indicator" });
    expect(org[1]!.shared[0]).toMatchObject({ category: "infrastructure", key: "ws-042" });
    const tenant = await g.incidentsSharing("10000000-0000-4000-8000-000000000001", { scope: "tenant" });
    expect(tenant[0]!.incident.label).toBe("I4 other customer");
    expect(tenant[0]!.shared.map((s) => s.category).sort()).toEqual(["indicator", "technique"]);
    const onlyTech = await g.incidentsSharing("10000000-0000-4000-8000-000000000001", { categories: ["technique"] });
    expect(onlyTech.map((s) => s.incident.label)).toEqual(["I3"]);
    await expect(g.incidentsSharing("10000000-0000-4000-8000-00000000ffff")).rejects.toMatchObject({ code: "not_found" });
  });

  it("vulnerabilities: KEV notification fires once per asset finding; exposure edges follow inventory", async () => {
    const { g, store, sink } = graph();
    const web = await g.ingestAsset({ organizationId: ORG_1, name: "web-01", hostname: "web-01", kind: "server", criticality: "high", internetFacing: true });
    const db = await g.ingestAsset({ organizationId: ORG_1, name: "db-01", hostname: "db-01", kind: "database", criticality: "crown_jewel" });
    await g.relate(web.id, "can_reach", db.id);
    const v = { organizationId: ORG_1, asset: web.id, cve: "cve-2024-3400", title: "PAN-OS command injection", cvss: 10, epss: 0.96, knownExploited: true, patchAvailable: true } as const;
    await g.ingestVulnerability(v);
    await g.ingestVulnerability(v);
    const kev = sink.items.filter((n) => n.type === "vulnerability.kev_detected");
    expect(kev).toHaveLength(1);
    expect(kev[0]).toMatchObject({ cve: "CVE-2024-3400", internetFacing: true, criticality: "high", organizationId: ORG_1 });

    const exposed = await g.exposedVulnerableReachingCritical(ORG_1);
    expect(exposed).toHaveLength(1);
    expect(exposed[0]!.asset.key).toBe("web-01");
    expect(exposed[0]!.reaches.map((n) => n.key)).toEqual(["db-01"]);
    expect(exposed[0]!.exploitability).toBeGreaterThan(0.9);

    const surface = await g.loadAttackSurface(ORG_1);
    expect(surface.nodes.map((n) => n.kind).sort()).toEqual(["data_store", "internet", "server", "vulnerability"]);
    expect(surface.truncated).toBe(false);

    await g.ingestAsset({ organizationId: ORG_1, name: "web-01", hostname: "web-01", kind: "server", internetFacing: false });
    const internet = await g.ensureInternet(ORG_1);
    expect(await store.edgesOf([internet.id], { direction: "out", edgeKinds: ["exposes"] })).toHaveLength(0);
    await expect(g.ingestVulnerability({ ...v, organizationId: ORG_2 })).rejects.toThrow(/organization/);
  });

  it("resolveRef creates natural-key refs only when asked", async () => {
    const { g } = graph();
    await expect(g.resolveRef({ organizationId: ORG_1, kind: "ip", key: "1.1.1.1" })).rejects.toBeInstanceOf(GraphError);
    const n = await g.resolveRef({ organizationId: ORG_1, kind: "ip", key: "1.1.1.1" }, true);
    expect(n.kind).toBe("ip");
  });
});
