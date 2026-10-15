import { describe, expect, it } from "vitest";
import { unwrapOtlpLogs } from "./otlp.js";

const envelope = (bodies: unknown[]) => ({
  resourceLogs: [{ resource: { attributes: [] }, scopeLogs: [{ scope: {}, logRecords: bodies.map((body) => ({ timeUnixNano: "1", body })) }] }],
});

describe("unwrapOtlpLogs", () => {
  it("returns undefined for non-OTLP payloads", () => {
    expect(unwrapOtlpLogs({ event_type: "alert" })).toBeUndefined();
    expect(unwrapOtlpLogs("plain line")).toBeUndefined();
    expect(unwrapOtlpLogs([{ a: 1 }])).toBeUndefined();
  });

  it("extracts JSON string bodies (Suricata EVE / Zeek) as an array", () => {
    const eve = '{"event_type":"alert","src_ip":"10.0.0.5"}';
    expect(unwrapOtlpLogs(envelope([{ stringValue: eve }, { stringValue: eve }]))).toEqual([eve, eve]);
  });

  it("joins plain-text bodies (syslog) with newlines", () => {
    expect(unwrapOtlpLogs(envelope([{ stringValue: "<34>Oct 11 22:14:15 host su: fail" }, { stringValue: "<34>Oct 11 22:14:16 host su: ok" }]))).toBe(
      "<34>Oct 11 22:14:15 host su: fail\n<34>Oct 11 22:14:16 host su: ok",
    );
  });

  it("converts kvlist bodies to objects and accepts a JSON string envelope", () => {
    const env = envelope([{ kvlistValue: { values: [{ key: "event_type", value: { stringValue: "dns" } }, { key: "port", value: { intValue: "53" } }] } }]);
    expect(unwrapOtlpLogs(JSON.stringify(env))).toEqual([{ event_type: "dns", port: 53 }]);
  });
});
