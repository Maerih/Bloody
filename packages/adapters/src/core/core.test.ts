import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { ctx } from "../test-support/fixtures.js";
import { defineAdapter, sanitizeLabels } from "./adapter.js";
import { lookupTechnique, normalizeTactic, technique, techniquesInText } from "./attack.js";
import { uuidV5 } from "./hash.js";
import { ObservableSet, parseHashList, refang } from "./indicators.js";
import { field, num, redactKeys } from "./json.js";
import { jsonRecords } from "./records.js";
import { isSensitiveKey } from "./severity.js";
import { parseTimestamp, toIso } from "./time.js";

describe("timestamps", () => {
  it("normalizes every engine dialect to ISO-8601 UTC", () => {
    expect(toIso("2026-10-07T08:15:02.481+0000")).toBe("2026-10-07T08:15:02.481Z");
    expect(toIso("2026-10-07T10:11:12.123456789Z")).toBe("2026-10-07T10:11:12.123Z");
    expect(toIso("2026-10-07T12:00:00+02:00")).toBe("2026-10-07T10:00:00.000Z");
    expect(toIso("2026-10-07 10:40:01.120334")).toBe("2026-10-07T10:40:01.120Z");
    expect(toIso(1791360000.123456)).toBe("2026-10-07T08:00:00.123Z");
    expect(toIso(1791370000000)).toBe("2026-10-07T10:46:40.000Z");
    expect(toIso("1791370000")).toBe("2026-10-07T10:46:40.000Z");
    expect(toIso("Wed Oct  7 10:20:00 2026 UTC")).toBe("2026-10-07T10:20:00.000Z");
    expect(toIso("Oct 07 2026 10:50:04")).toBe("2026-10-07T10:50:04.000Z");
    expect(toIso("Tue, 06 Oct 2026 10:00:00 GMT")).toBe("2026-10-06T10:00:00.000Z");
    expect(toIso("Oct  7 10:50:02", { reference: new Date("2026-10-07T12:00:00Z") })).toBe("2026-10-07T10:50:02.000Z");
    expect(toIso("1970-01-01T00:00:00")).toBeUndefined();
    expect(toIso("2026-13-45T00:00:00Z")).toBeUndefined();
    expect(parseTimestamp("garbage")).toBeUndefined();
  });
});

describe("payload splitting", () => {
  it("JSON, JSON Lines (with bad lines), arrays of JSON strings and gzip bytes", () => {
    const items = [...jsonRecords('{"a":1}\n\n# comment\n{bad}\n{"a":2}')];
    expect(items.map((i) => (i.ok ? "ok" : "err"))).toEqual(["ok", "err", "ok"]);
    expect([...jsonRecords(['{"a":1}', '{"a":2}'])].filter((i) => i.ok)).toHaveLength(2);
    expect([...jsonRecords(new Uint8Array(gzipSync(Buffer.from('[{"a":1},{"a":2},{"a":3}]'))))].filter((i) => i.ok)).toHaveLength(3);
    expect([...jsonRecords({ Records: [1, 2] }, { unwrap: (o) => o["Records"] as unknown[] })]).toHaveLength(2);
    expect([...jsonRecords(42)][0]).toMatchObject({ ok: false });
  });

  it("caps records per payload and reports truncation", () => {
    const a = defineAdapter({ key: "zeek", version: "0.0.1", name: "t", sourceKind: "network", consumes: [], map: () => ({ category: "network", eventType: "t.e" }) });
    const r = a.normalizeDetailed([{}, {}, {}], ctx({ maxRecords: 2 }));
    expect(r.events).toHaveLength(2);
    expect(r.truncated).toBe(true);
  });
});

describe("canonical event finalization", () => {
  const a = defineAdapter({
    key: "zeek",
    version: "0.0.1",
    name: "t",
    sourceKind: "network",
    consumes: [],
    map: (r) => {
      const rec = r as Record<string, unknown>;
      if (rec["throw"]) throw new Error("boom");
      return { category: "network", eventType: "t.e", timestamp: rec["ts"] as string | undefined, severity: rec["sev"] as "high" | undefined, labels: { "bad key!": "x", n: 5, empty: "" }, raw: rec };
    },
    redactRaw: (r) => redactKeys(r, isSensitiveKey),
  });

  it("falls back to receivedAt with an explicit label, sanitizes labels, redacts raw secrets", () => {
    const [e] = a.normalize([{ password: "p", token: "t", keep: 1 }], ctx());
    expect(e?.timestamp).toBe("2026-10-07T12:00:00.000Z");
    expect(e?.labels).toEqual({ bad_key_: "x", n: "5", timestamp_source: "received_at" });
    expect(e?.provenance.raw).toEqual({ password: "[REDACTED]", token: "[REDACTED]", keep: 1 });
    expect(e?.source).toEqual({ kind: "network", product: "zeek", integrationId: "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d" });
    expect(e?.severity).toBe("info");
  });

  it("mapper exceptions and schema violations become per-record rejections", () => {
    const r = a.normalizeDetailed([{ throw: true }, { sev: "extreme" }, {}], ctx());
    expect(r.events).toHaveLength(1);
    expect(r.rejected.map((x) => x.reason)).toEqual(["mapping failed: boom", expect.stringContaining("schema validation failed: severity")]);
  });

  it("label limits", () => {
    const many = Object.fromEntries(Array.from({ length: 80 }, (_, i) => [`k${i}`, "v".repeat(2000)]));
    const out = sanitizeLabels(many);
    expect(Object.keys(out)).toHaveLength(64);
    expect(out["k0"]?.length).toBe(1024);
  });

  it("uuidV5 is stable and namespace-scoped", () => {
    const ns = "6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b";
    expect(uuidV5("x", ns)).toBe(uuidV5("x", ns));
    expect(uuidV5("x", ns)).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(() => uuidV5("x", "nope")).toThrow();
  });
});

describe("ATT&CK helpers", () => {
  it("looks up, validates and extracts techniques", () => {
    expect(lookupTechnique("t1059.001")).toEqual({ id: "T1059.001", name: "PowerShell", tactic: "Execution" });
    expect(technique("T9999")).toEqual({ id: "T9999" });
    expect(technique("TA0001")).toBeUndefined();
    expect(technique("T1110", undefined, "credential-access")).toEqual({ id: "T1110", name: "Brute Force", tactic: "Credential Access" });
    expect(techniquesInText(["attack.t1003.001", "mitre_execution"], "see T1059 and T1059")).toEqual([
      { id: "T1003.001", name: "LSASS Memory", tactic: "Credential Access" },
      { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
    ]);
    expect(normalizeTactic("mitre_command_and_control")).toBe("Command and Control");
    expect(normalizeTactic("TA0006")).toBe("Credential Access");
    expect(normalizeTactic("nonsense")).toBeUndefined();
  });
});

describe("observables", () => {
  it("refangs, normalizes and skips internal infrastructure", () => {
    expect(refang("hxxps://evil[.]example[.]net/a")).toBe("https://evil.example.net/a");
    const set = new ObservableSet()
      .add("ip", "10.0.0.1")
      .add("ip", "198.51.100.7:443")
      .add("domain", "FILESERVER.corp.local")
      .add("domain", "Evil.Example.NET.")
      .addHost("8.8.4.4")
      .addHash("D41D8CD98F00B204E9800998ECF8427E")
      .add("cve", "cve-2024-3094")
      .add("email", "not-an-email");
    expect(set.toArray()).toEqual([
      { type: "ip", value: "198.51.100.7" },
      { type: "domain", value: "evil.example.net" },
      { type: "ip", value: "8.8.4.4" },
      { type: "md5", value: "d41d8cd98f00b204e9800998ecf8427e" },
      { type: "cve", value: "CVE-2024-3094" },
    ]);
    expect(parseHashList("SHA1=AA,MD5=D41D8CD98F00B204E9800998ECF8427E,IMPHASH=00")).toEqual({ md5: "d41d8cd98f00b204e9800998ecf8427e" });
  });

  it("json accessors tolerate vendor quirks", () => {
    expect(field({ "id.orig_h": "1.2.3.4" }, "id.orig_h")).toBe("1.2.3.4");
    expect(field({ id: { orig_h: "1.2.3.4" } }, "id.orig_h")).toBe("1.2.3.4");
    expect(num("0x1a2b")).toBe(6699);
    expect(num("12abc")).toBeUndefined();
    expect(isSensitiveKey("secretaccesskey")).toBe(true);
    expect(isSensitiveKey("accesskeyid")).toBe(false);
  });
});
