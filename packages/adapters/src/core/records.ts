import { gunzipSync } from "node:zlib";
import { isRecord, type JsonRecord } from "./json.js";

/**
 * Splitting raw engine payloads into records. Adapters receive whatever the transport
 * delivered: a parsed object (webhook), an array (batch API), a JSON or JSON-Lines string
 * (file drop / Kafka value) or raw bytes (possibly gzip-compressed log files).
 */

export type SplitItem = { ok: true; index: number; value: unknown } | { ok: false; index: number; error: string };

/** Decompressed payloads larger than this are refused (zip-bomb guard). */
export const DEFAULT_MAX_PAYLOAD_BYTES = 256 * 1024 * 1024;

function isBytes(raw: unknown): raw is Uint8Array {
  return raw instanceof Uint8Array;
}

/** Decode bytes (gunzip when gzip magic is present) or pass strings through. */
export function payloadToText(raw: unknown, maxBytes = DEFAULT_MAX_PAYLOAD_BYTES): string | undefined {
  if (typeof raw === "string") return raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
  let bytes: Uint8Array | undefined;
  if (isBytes(raw)) bytes = raw;
  else if (raw instanceof ArrayBuffer) bytes = new Uint8Array(raw);
  if (!bytes) return undefined;
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    bytes = gunzipSync(bytes, { maxOutputLength: maxBytes });
  }
  if (bytes.length > maxBytes) throw new RangeError(`payload exceeds ${maxBytes} bytes`);
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

export interface JsonRecordsOptions {
  /** Unwrap a container object into its records (e.g. CloudTrail `{Records:[…]}`). */
  unwrap?: (obj: JsonRecord) => unknown[] | undefined;
  maxBytes?: number;
}

function* fromValue(value: unknown, opts: JsonRecordsOptions, start: number): Generator<SplitItem> {
  if (Array.isArray(value)) {
    let i = start;
    for (const v of value) {
      if (typeof v === "string" && /^\s*[[{]/.test(v)) {
        // arrays of JSON strings (e.g. Kafka batch values)
        for (const item of fromText(v, opts, i)) {
          yield item;
          i = item.index + 1;
        }
        continue;
      }
      if (isRecord(v) && opts.unwrap) {
        const inner = opts.unwrap(v);
        if (inner) {
          for (const x of inner) yield { ok: true, index: i++, value: x };
          continue;
        }
      }
      yield { ok: true, index: i++, value: v };
    }
    return;
  }
  if (isRecord(value)) {
    const inner = opts.unwrap?.(value);
    if (inner) {
      let i = start;
      for (const x of inner) yield { ok: true, index: i++, value: x };
      return;
    }
    yield { ok: true, index: start, value };
    return;
  }
  yield { ok: false, index: start, error: `unsupported payload type: ${value === null ? "null" : typeof value}` };
}

function* fromText(text: string, opts: JsonRecordsOptions, start: number): Generator<SplitItem> {
  const t = text.trim();
  if (t === "") return;
  if (t.startsWith("[") || t.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(t);
      yield* fromValue(parsed, opts, start);
      return;
    } catch {
      // fall through to JSON Lines
    }
  }
  const lines = t.split(/\r?\n/);
  let index = start;
  for (let n = 0; n < lines.length; n++) {
    const line = (lines[n] ?? "").trim();
    if (line === "" || line.startsWith("#")) continue;
    try {
      const parsed: unknown = JSON.parse(line);
      if (isRecord(parsed) && opts.unwrap) {
        const inner = opts.unwrap(parsed);
        if (inner) {
          for (const x of inner) yield { ok: true, index: index++, value: x };
          continue;
        }
      }
      yield { ok: true, index: index++, value: parsed };
    } catch (err) {
      yield { ok: false, index: index++, error: `line ${n + 1}: invalid JSON (${(err as Error).message.slice(0, 120)})` };
    }
  }
}

/** Records from JSON / JSON-Lines / arrays / objects / (gzipped) bytes. */
export function* jsonRecords(raw: unknown, opts: JsonRecordsOptions = {}): Generator<SplitItem> {
  if (typeof raw === "string" || isBytes(raw) || raw instanceof ArrayBuffer) {
    let text: string | undefined;
    try {
      text = payloadToText(raw, opts.maxBytes);
    } catch (err) {
      yield { ok: false, index: 0, error: `payload could not be decoded: ${(err as Error).message}` };
      return;
    }
    if (text !== undefined) yield* fromText(text, opts, 0);
    return;
  }
  yield* fromValue(raw, opts, 0);
}

/**
 * Text lines (syslog, CEF). Accepts a string / bytes (one record per line), an array of
 * strings, or objects carrying the line under `message` / `msg` / `line` (Vector, Fluent Bit
 * and syslog-ng JSON envelopes).
 */
export function* textRecords(raw: unknown, maxBytes?: number): Generator<SplitItem> {
  const lineOf = (v: unknown): string | undefined => {
    if (typeof v === "string") return v;
    if (isRecord(v)) {
      for (const k of ["message", "msg", "line", "log", "raw"]) {
        const x = v[k];
        if (typeof x === "string") return x;
      }
    }
    return undefined;
  };
  if (typeof raw === "string" || isBytes(raw) || raw instanceof ArrayBuffer) {
    let text: string | undefined;
    try {
      text = payloadToText(raw, maxBytes);
    } catch (err) {
      yield { ok: false, index: 0, error: `payload could not be decoded: ${(err as Error).message}` };
      return;
    }
    if (text === undefined) return;
    let i = 0;
    for (const line of text.split(/\r?\n/)) {
      if (line.trim() === "") continue;
      yield { ok: true, index: i++, value: line };
    }
    return;
  }
  const items = Array.isArray(raw) ? raw : [raw];
  let i = 0;
  for (const item of items) {
    const line = lineOf(item);
    if (line === undefined) yield { ok: false, index: i++, error: "record is not a text line" };
    else if (line.trim() !== "") yield { ok: true, index: i++, value: line };
  }
}
