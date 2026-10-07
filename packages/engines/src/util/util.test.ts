import { describe, expect, it } from "vitest";
import { ManualClock, toEpochMs } from "./clock.js";
import { MinHeap } from "./heap.js";
import { cidrContains, isNonPublicIp, isPublicIp, normalizeIp, parseCidr, parseIp } from "./ip.js";
import { haversineKm, noisyOr, saturate } from "./math.js";
import { canonicalJson, contentHash, stableId, uuidV5 } from "./uuid.js";

describe("uuid", () => {
  it("produces deterministic RFC 4122 v5 ids", () => {
    const a = uuidV5("hello");
    expect(a).toBe(uuidV5("hello"));
    expect(a).not.toBe(uuidV5("hello2"));
    expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
  it("stableId separates parts unambiguously", () => {
    expect(stableId("a", "bc")).not.toBe(stableId("ab", "c"));
    expect(stableId("x", null)).not.toBe(stableId("x", "null"));
  });
  it("canonical JSON ignores key order", () => {
    expect(canonicalJson({ b: 1, a: { d: 2, c: 3 } })).toBe(canonicalJson({ a: { c: 3, d: 2 }, b: 1 }));
    expect(contentHash({ b: 1, a: 2 })).toBe(contentHash({ a: 2, b: 1 }));
  });
});

describe("ip", () => {
  it("parses and normalizes v4, v6 and v4-mapped v6", () => {
    expect(normalizeIp("10.0.0.1")).toBe("10.0.0.1");
    expect(normalizeIp("2001:0db8:0000:0000:0000:0000:0000:0001")).toBe("2001:db8::1");
    expect(normalizeIp("[fe80::1%eth0]")).toBe("fe80::1");
    expect(normalizeIp("::ffff:192.0.2.5")).toBe("192.0.2.5");
    expect(normalizeIp("::")).toBe("::");
    expect(normalizeIp("1:0:0:1:0:0:0:1")).toBe("1:0:0:1::1");
    expect(parseIp("256.1.1.1")).toBeNull();
    expect(parseIp("01.2.3.4")).toBeNull();
    expect(parseIp("1::2::3")).toBeNull();
    expect(parseIp("not-an-ip")).toBeNull();
  });
  it("evaluates CIDR membership for both families", () => {
    expect(cidrContains("10.0.0.0/8", "10.200.3.4")).toBe(true);
    expect(cidrContains("10.0.0.0/8", "11.0.0.1")).toBe(false);
    expect(cidrContains("2001:db8::/32", "2001:db8:ffff::1")).toBe(true);
    expect(cidrContains("2001:db8::/32", "10.0.0.1")).toBe(false);
    expect(cidrContains("0.0.0.0/0", "8.8.8.8")).toBe(true);
    expect(parseCidr("10.0.0.0/33")).toBeNull();
    expect(parseCidr("10.0.0.1")).toEqual({ version: 4, network: BigInt(0x0a000001), prefix: 32 });
  });
  it("classifies public vs non-public space", () => {
    for (const ip of ["10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "100.64.0.1", "169.254.1.1", "::1", "fd00::1", "fe80::1"]) expect(isNonPublicIp(ip)).toBe(true);
    for (const ip of ["8.8.8.8", "203.0.113.50", "2606:4700::1111"]) expect(isPublicIp(ip)).toBe(true);
    expect(isPublicIp("garbage")).toBe(false);
  });
});

describe("math", () => {
  it("saturates counts so volume cannot dominate", () => {
    expect(saturate(0, 3)).toBe(0);
    expect(saturate(3, 3)).toBe(0.5);
    expect(saturate(1_000_000, 3)).toBeLessThan(1);
    expect(saturate(-1, 3)).toBe(0);
  });
  it("noisy-OR combines independent probabilities", () => {
    expect(noisyOr([])).toBe(0);
    expect(noisyOr([0.5, 0.5])).toBeCloseTo(0.75);
    expect(noisyOr([1, 0.2])).toBe(1);
  });
  it("haversine distance Paris–Singapore ≈ 10 730 km", () => {
    expect(haversineKm(48.8566, 2.3522, 1.3521, 103.8198)).toBeGreaterThan(10_600);
    expect(haversineKm(48.8566, 2.3522, 1.3521, 103.8198)).toBeLessThan(10_800);
  });
});

describe("clock & heap", () => {
  it("manual clock is settable and advanceable", () => {
    const c = new ManualClock("2026-01-01T00:00:00Z");
    c.advance(1000);
    expect(c.now()).toBe(Date.parse("2026-01-01T00:00:01Z"));
    expect(() => toEpochMs("nope")).toThrow(RangeError);
  });
  it("min-heap pops in priority order, FIFO on ties", () => {
    const h = new MinHeap<string>();
    h.push("c", 3);
    h.push("a", 1);
    h.push("b1", 2);
    h.push("b2", 2);
    expect([h.pop(), h.pop(), h.pop(), h.pop(), h.pop()]).toEqual(["a", "b1", "b2", "c", undefined]);
  });
});
