import { describe, expect, it } from "vitest";
import { HostPatchStatus, gradePatching, osSupport } from "./patching.js";

const NOW = new Date("2026-10-16T12:00:00Z");

describe("osSupport", () => {
  it("knows Windows 11 feature updates per edition", () => {
    expect(osSupport("Microsoft Windows 11 Pro 10.0.26100", NOW)).toMatchObject({ product: "Windows 11 24H2", endsOn: "2026-10-13", status: "ended" });
    expect(osSupport("Microsoft Windows 11 Enterprise 10.0.26100", NOW)).toMatchObject({ product: "Windows 11 24H2 Enterprise / Education", endsOn: "2027-10-12", status: "supported" });
    expect(osSupport("Microsoft Windows 11 Enterprise 10.0.22631", NOW)).toMatchObject({ endsOn: "2026-11-10", status: "ending_soon" });
    expect(osSupport("Microsoft Windows 11 Pro 10.0.26200", NOW)).toMatchObject({ product: "Windows 11 25H2", status: "supported" });
    expect(osSupport("Microsoft Windows 11 Pro 10.0.26300", NOW)).toMatchObject({ status: "supported", endsOn: null });
  });

  it("knows Windows 10, LTSC and Windows Server", () => {
    expect(osSupport("Microsoft Windows 10 Pro 10.0.19045", NOW)).toMatchObject({ product: "Windows 10", status: "ended", note: expect.stringContaining("Extended Security Updates") });
    expect(osSupport("Microsoft Windows 10 Enterprise LTSC 2021 10.0.19044", NOW)).toMatchObject({ product: "Windows 10 Enterprise LTSC 2021", status: "ending_soon", endsOn: "2027-01-12" });
    expect(osSupport("Microsoft Windows Server 2016 Standard 10.0.14393", NOW)).toMatchObject({ status: "ending_soon", endsOn: "2027-01-12" });
    expect(osSupport("Microsoft Windows Server 2012 R2 Datacenter 6.3.9600", NOW).status).toBe("ended");
    expect(osSupport("Microsoft Windows Server 2022 Standard 10.0.20348", NOW).status).toBe("supported");
  });

  it("knows Linux distributions and macOS", () => {
    expect(osSupport("Ubuntu 20.04.6 LTS", NOW)).toMatchObject({ product: "Ubuntu 20.04", status: "ended" });
    expect(osSupport("Ubuntu 24.04.1 LTS", NOW)).toMatchObject({ status: "supported" });
    expect(osSupport("Debian GNU/Linux 11 (bullseye)", NOW)).toMatchObject({ status: "ended" });
    expect(osSupport("Debian GNU/Linux 12 (bookworm)", NOW).status).toBe("supported");
    expect(osSupport("Rocky Linux 8.9 (Green Obsidian)", NOW)).toMatchObject({ product: "Rocky Linux 8", status: "supported" });
    expect(osSupport("CentOS Linux 7 (Core)", NOW).status).toBe("ended");
    expect(osSupport("Red Hat Enterprise Linux 9.4 (Plow)", NOW)).toMatchObject({ product: "Red Hat Enterprise Linux 9", status: "supported" });
    expect(osSupport("macOS 14.7", NOW).status).toBe("ended");
    expect(osSupport("macOS 26.1", NOW).status).toBe("supported");
    expect(osSupport("FreeBSD 14", NOW).status).toBe("unknown");
    expect(osSupport(null, NOW).status).toBe("unknown");
  });
});

describe("gradePatching", () => {
  const status = (over: object = {}) => HostPatchStatus.parse({ source: "apt", pending: [], rebootRequired: false, lastCheckedAt: "2026-10-16T06:00:00Z", ...over });
  const supported = osSupport("Ubuntu 24.04 LTS", NOW);
  const sec = { title: "openssl", id: "openssl", version: "3.0.13-0ubuntu3.5", security: true };

  it("is current with nothing outstanding", () => {
    expect(gradePatching({ status: status(), os: supported, securityPendingSince: null, now: NOW })).toEqual({ state: "current", reasons: [] });
    expect(gradePatching({ status: status({ pending: [{ title: "vim", security: false }] }), os: supported, securityPendingSince: null, now: NOW })).toEqual({ state: "current", reasons: ["1 non-security update available"] });
  });

  it("is behind with security updates or a restart waiting, breached after the SLA", () => {
    expect(gradePatching({ status: status({ pending: [sec] }), os: supported, securityPendingSince: "2026-10-10T00:00:00Z", now: NOW })).toEqual({ state: "behind", reasons: ["1 security update waiting"] });
    expect(gradePatching({ status: status({ pending: [sec] }), os: supported, securityPendingSince: "2026-09-01T00:00:00Z", now: NOW })).toEqual({ state: "breached", reasons: ["1 security update outstanding for 45 days (SLA 30)"] });
    expect(gradePatching({ status: status({ rebootRequired: true }), os: supported, securityPendingSince: null, now: NOW }).state).toBe("behind");
    expect(gradePatching({ status: status({ lastCheckedAt: "2026-08-01T00:00:00Z" }), os: supported, securityPendingSince: null, now: NOW }).reasons).toEqual(["Has not looked for updates in 76 days"]);
  });

  it("is breached on an unsupported OS, and unknown without data", () => {
    const g = gradePatching({ status: status(), os: osSupport("Microsoft Windows 10 Pro 10.0.19045", NOW), securityPendingSince: null, now: NOW });
    expect(g).toEqual({ state: "breached", reasons: ["Windows 10 no longer gets security updates (since 2025-10-14)"] });
    expect(gradePatching({ status: null, os: supported, securityPendingSince: null, now: NOW }).state).toBe("unknown");
    expect(gradePatching({ status: status({ error: "apt lists are missing" }), os: supported, securityPendingSince: null, now: NOW }).state).toBe("unknown");
  });

  it("normalizes severities", () => {
    expect(HostPatchStatus.parse({ source: "windows_update", pending: [{ title: "x", severity: "Critical", security: true }, { title: "y", severity: "weird" }] }).pending.map((p) => p.severity)).toEqual(["critical", "unspecified"]);
  });
});
