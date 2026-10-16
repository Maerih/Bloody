import { describe, expect, it } from "vitest";
import { HostInventoryReport, antivirusIssues, antivirusStatusOf } from "./host-inventory.js";

const defender = { name: "Microsoft Defender Antivirus", enabled: true, upToDate: true, realTimeProtection: true, tamperProtection: true, signatureAgeDays: 0 };

describe("host inventory", () => {
  it("judges antivirus health and explains the problems", () => {
    expect(antivirusStatusOf([])).toBe("unmanaged");
    expect(antivirusStatusOf([defender])).toBe("protected");
    const tampered = { ...defender, realTimeProtection: false, tamperProtection: false };
    expect(antivirusStatusOf([tampered])).toBe("unhealthy");
    expect(antivirusIssues([tampered])).toEqual(["Microsoft Defender Antivirus: real-time protection is off", "Microsoft Defender Antivirus: tamper protection is off"]);
    expect(antivirusStatusOf([{ ...defender, signatureAgeDays: 12, upToDate: null }])).toBe("unhealthy");
    expect(antivirusIssues([{ ...defender, signatureAgeDays: 12, upToDate: null }])).toEqual(["Microsoft Defender Antivirus: definitions are 12 days old"]);
    // A second, healthy product keeps the endpoint protected (e.g. Defender passive beside ESET).
    expect(antivirusStatusOf([{ ...defender, enabled: false }, { name: "ESET", enabled: true, upToDate: true, realTimeProtection: null, tamperProtection: null, signatureAgeDays: null }])).toBe("protected");
  });

  it("validates and normalizes agent reports", () => {
    const r = HostInventoryReport.parse({
      services: [{ name: "WinDefend", displayName: "", state: "Running", startMode: "Auto" }],
      users: [{ name: "amina", admin: true }],
      antivirus: [{ name: "ClamAV", enabled: true }],
    });
    expect(r.services[0]).toEqual({ name: "WinDefend", displayName: null, state: "running", startMode: "auto", account: null });
    expect(r.users[0]).toMatchObject({ admin: true, enabled: true, loggedIn: false });
    expect(r.antivirus[0]).toMatchObject({ upToDate: null, realTimeProtection: null });
    expect(r.software).toEqual([]);
    expect(HostInventoryReport.safeParse({ extra: 1 }).success).toBe(false);
  });
});
