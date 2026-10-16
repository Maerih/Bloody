import { describe, expect, it } from "vitest";
import { EXPOSURE_PORTS, exposurePort, isPublicAddress, normalizeAddress } from "./external-exposure.js";

describe("external exposure", () => {
  it("only treats globally routable addresses as checkable", () => {
    for (const ip of ["41.90.64.10", "102.68.1.7", "8.8.8.8", "2c0f:fe38:2000::1", "2a00:1450:4001::200e", "::ffff:41.90.64.10"]) expect(isPublicAddress(ip), ip).toBe(true);
    for (const ip of ["10.0.0.5", "172.16.4.1", "172.31.255.255", "192.168.1.1", "127.0.0.1", "100.64.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "192.0.2.10", "198.51.100.1", "203.0.113.9", "198.18.0.1", "::1", "fe80::1", "fd00::1", "2001:db8::1", "::ffff:10.0.0.1", "999.1.1.1", "not-an-ip", ""])
      expect(isPublicAddress(ip), ip).toBe(false);
    expect(isPublicAddress("172.32.0.1")).toBe(true);
  });

  it("normalizes IPv4-mapped addresses and has a unique port catalogue", () => {
    expect(normalizeAddress("::FFFF:41.90.64.10")).toBe("41.90.64.10");
    expect(normalizeAddress("2A00:1450::1")).toBe("2a00:1450::1");
    expect(new Set(EXPOSURE_PORTS.map((p) => p.port)).size).toBe(EXPOSURE_PORTS.length);
    expect(exposurePort(3389)).toMatchObject({ service: "Remote Desktop (RDP)", severity: "critical" });
    expect(exposurePort(443)).toBeUndefined();
  });
});
