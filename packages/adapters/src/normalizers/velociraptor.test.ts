import { describe, expect, it } from "vitest";
import { assertSchemaValid, byType, ctx, fixtureText } from "../test-support/fixtures.js";
import { artifactFamily, createVelociraptorAdapter } from "./velociraptor.js";

const adapter = createVelociraptorAdapter();

describe("Velociraptor adapter", () => {
  it("collection envelope (Pslist) → process events attributed to the client", () => {
    const events = adapter.normalize(fixtureText("velociraptor/pslist-collection.json"), ctx());
    expect(events).toHaveLength(2);
    assertSchemaValid(events);
    const ps = events[0];
    expect(ps?.category).toBe("process");
    expect(ps?.timestamp).toBe("2026-10-07T10:00:00.987Z");
    expect(ps?.asset).toEqual({ hostname: "WS-ALICE.corp.local", agentId: "C.4f3e2d1c0b0a9988" });
    expect(ps?.process).toMatchObject({ pid: 7344, name: "powershell.exe", user: "CORP\\alice", parent: { pid: 5120 } });
    expect(ps?.labels).toMatchObject({ "velociraptor.artifact": "Windows.System.Pslist", "velociraptor.flow_id": "F.CR2T8Q1NJ5K0" });
  });

  const result = adapter.normalizeDetailed(fixtureText("velociraptor/hunt-export.jsonl"), ctx());

  it("hunt export rows: YARA, netstat, EVTX, client info, Hayabusa; rows without artifact are skipped", () => {
    expect(result.events).toHaveLength(5);
    expect(result.skipped[0]?.reason).toContain("_Source");
    assertSchemaValid(result.events);
  });

  it("YARA hit is a high-severity detection timed by the collection (_ts)", () => {
    const y = byType(result.events, "velociraptor.yara_match");
    expect(y.severity).toBe("high");
    expect(y.timestamp).toBe("2026-10-07T10:30:00.000Z");
    expect(y.detection).toMatchObject({ ruleId: "CobaltStrike_Beacon_Encoded", engine: "yara" });
    expect(y.attack[0]?.id).toBe("T1055");
  });

  it("EVTX rows go through the Windows event model", () => {
    const e = byType(result.events, "windows.logon_failure");
    expect(e.asset?.hostname).toBe("DC01.corp.local");
    expect(e.identity).toMatchObject({ principal: "CORP\\administrator", sourceIp: "203.0.113.77" });
    expect(e.timestamp).toBe("2026-10-07T10:05:00.000Z");
  });

  it("netstat / client info / sigma", () => {
    expect(byType(result.events, "velociraptor.Windows.Network.Netstat").network).toMatchObject({ dstIp: "198.51.100.23", dstPort: 443, direction: "outbound" });
    const info = byType(result.events, "velociraptor.client_info");
    expect(info.asset).toMatchObject({ os: "windows 10.0.22631", mac: ["00:15:5d:01:02:03"] });
    expect(info.labels["timestamp_source"]).toBe("received_at");
    const sigma = byType(result.events, "velociraptor.sigma_match");
    expect(sigma.severity).toBe("high");
    expect(sigma.attack[0]?.id).toBe("T1059.001");
  });

  it("artifact families", () => {
    expect(artifactFamily("Linux.Sys.Pslist")).toBe("process");
    expect(artifactFamily("Windows.Detection.Yara.NTFS")).toBe("yara");
    expect(artifactFamily("Windows.Sys.StartupItems")).toBe("persistence");
    expect(artifactFamily("Windows.NTFS.MFT")).toBe("file");
    expect(artifactFamily("Custom.Something")).toBe("generic");
  });
});
