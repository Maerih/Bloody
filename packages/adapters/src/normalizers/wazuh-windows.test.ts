import { describe, expect, it } from "vitest";
import { assertSchemaValid, byType, ctx, fixtureText } from "../test-support/fixtures.js";
import { createWazuhAdapter } from "./wazuh.js";
import { mapWindowsEvent, splitDomainUser } from "./windows.js";

const events = createWazuhAdapter().normalize(fixtureText("wazuh/windows.jsonl"), ctx());

describe("Windows Security & Sysmon via Wazuh (data.win.*)", () => {
  it("normalizes all seven events and they validate against IngestEvent", () => {
    expect(events).toHaveLength(7);
    assertSchemaValid(events);
  });

  it("Sysmon 1: process + parent + hashes + user + rule technique", () => {
    const e = byType(events, "sysmon.process_create");
    expect(e.category).toBe("process");
    expect(e.severity).toBe("high");
    expect(e.process).toMatchObject({
      pid: 7344,
      name: "powershell.exe",
      commandLine: expect.stringContaining("-enc"),
      user: "CORP\\alice",
      parent: { pid: 5120, name: "WINWORD.EXE" },
    });
    expect(e.process?.hashSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(e.user).toEqual({ domain: "CORP", name: "alice" });
    expect(e.attack).toEqual([{ id: "T1059.001", name: "PowerShell", tactic: "Execution" }]);
    expect(e.indicators.map((i) => i.type).sort()).toEqual(["md5", "sha1", "sha256"]);
    expect(e.labels["windows.event_id"]).toBe("1");
  });

  it("Sysmon 3: outbound network connection with destination indicators", () => {
    const e = byType(events, "sysmon.network_connection");
    expect(e.network).toMatchObject({ srcIp: "10.0.10.21", dstIp: "198.51.100.23", dstPort: 443, protocol: "tcp", direction: "outbound" });
    expect(e.indicators).toEqual(expect.arrayContaining([{ type: "ip", value: "198.51.100.23" }, { type: "domain", value: "cdn-update.badcdn.net" }]));
    expect(e.indicators.some((i) => i.value === "10.0.10.21")).toBe(false);
  });

  it("Sysmon 10 on lsass: raises severity to high and adds T1003.001", () => {
    const e = byType(events, "sysmon.process_access");
    expect(e.severity).toBe("high");
    expect(e.attack.map((t) => t.id)).toContain("T1003.001");
    expect(e.labels["target.image"]).toMatch(/lsass\.exe$/);
  });

  it("4625: failed network logon with identity, source IP and status codes", () => {
    const e = byType(events, "windows.logon_failure");
    expect(e.category).toBe("authentication");
    expect(e.outcome).toBe("failure");
    expect(e.identity).toMatchObject({ provider: "windows", principal: "CORP\\administrator", sourceIp: "203.0.113.77", outcome: "failure" });
    expect(e.labels).toMatchObject({ "logon.type": "3", "logon.sub_status": "0xc000006a" });
  });

  it("4728 into Domain Admins: identity event raised to high", () => {
    const e = byType(events, "windows.member_added_global_group");
    expect(e.category).toBe("identity");
    expect(e.severity).toBe("high");
    expect(e.labels["actor"]).toBe("CORP\\svc_backup");
    expect(e.labels["group"]).toBe("Domain Admins");
  });

  it("Sysmon 22 DNS and 1102 log clearing", () => {
    const dns = byType(events, "sysmon.dns_query");
    expect(dns.network?.dnsQuery).toBe("cdn-update.badcdn.net");
    expect(dns.indicators).toContainEqual({ type: "ip", value: "198.51.100.23" });
    const cleared = byType(events, "windows.audit_log_cleared");
    expect(cleared.severity).toBe("high");
    expect(cleared.attack[0]?.id).toBe("T1070.001");
  });

  it("mapping is case-insensitive (raw EVTX PascalCase) and ignores unmodelled ids", () => {
    const m = mapWindowsEvent({ EventID: "4624", Channel: "Security" }, { TargetUserName: "bob", TargetDomainName: "CORP", IpAddress: "198.51.100.5", LogonType: "10" });
    expect(m?.draft.eventType).toBe("windows.logon_success");
    expect(m?.draft.identity).toMatchObject({ principal: "CORP\\bob", sourceIp: "198.51.100.5", outcome: "success" });
    expect(mapWindowsEvent({ eventID: "9999", channel: "Security" }, {})).toBeUndefined();
    expect(splitDomainUser("alice@corp.example")).toEqual({ name: "alice", domain: "corp.example" });
  });
});
