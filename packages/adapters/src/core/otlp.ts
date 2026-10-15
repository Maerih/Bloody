import { isRecord } from "./json.js";

/** An OTLP/JSON AnyValue (opentelemetry-proto common.v1.AnyValue, JSON mapping). */
function anyValue(v: unknown): unknown {
  if (!isRecord(v)) return v;
  if ("stringValue" in v) return v.stringValue;
  if ("boolValue" in v) return v.boolValue;
  if ("intValue" in v) return Number(v.intValue);
  if ("doubleValue" in v) return v.doubleValue;
  if ("bytesValue" in v) return v.bytesValue;
  if (isRecord(v.arrayValue)) return (Array.isArray(v.arrayValue.values) ? v.arrayValue.values : []).map(anyValue);
  if (isRecord(v.kvlistValue)) {
    const out: Record<string, unknown> = {};
    for (const kv of Array.isArray(v.kvlistValue.values) ? v.kvlistValue.values : []) {
      if (isRecord(kv) && typeof kv.key === "string") out[kv.key] = anyValue(kv.value);
    }
    return out;
  }
  return undefined;
}

/**
 * Unwrap an OTLP/JSON logs export (`{resourceLogs:[{scopeLogs:[{logRecords:[{body}]}]}]}`, as sent by the
 * OpenTelemetry Collector's otlphttp/otlp_json exporters) into the raw engine records carried in each
 * log body. Returns undefined when `raw` is not an OTLP logs envelope, so callers can pass the payload
 * through unchanged. All-text bodies (e.g. syslog lines) become newline-joined text; anything else an array.
 */
export function unwrapOtlpLogs(raw: unknown): unknown {
  let obj = raw;
  if (typeof raw === "string" && raw.trimStart().startsWith("{") && raw.includes('"resourceLogs"')) {
    try {
      obj = JSON.parse(raw);
    } catch {
      return undefined;
    }
  }
  if (!isRecord(obj) || !Array.isArray(obj.resourceLogs)) return undefined;
  const bodies: unknown[] = [];
  for (const rl of obj.resourceLogs) {
    if (!isRecord(rl)) continue;
    const scopes = Array.isArray(rl.scopeLogs) ? rl.scopeLogs : Array.isArray(rl.instrumentationLibraryLogs) ? rl.instrumentationLibraryLogs : [];
    for (const sl of scopes) {
      if (!isRecord(sl) || !Array.isArray(sl.logRecords)) continue;
      for (const lr of sl.logRecords) {
        if (!isRecord(lr)) continue;
        const body = anyValue(lr.body);
        if (body !== undefined && body !== null && body !== "") bodies.push(body);
      }
    }
  }
  const allPlainText = bodies.length > 0 && bodies.every((b) => typeof b === "string" && !/^\s*[[{]/.test(b));
  return allPlainText ? (bodies as string[]).join("\n") : bodies;
}
