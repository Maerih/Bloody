/**
 * Minimal Apple property-list (XML plist) codec for the MDM protocol (proprietary).
 * Covers the subset Apple MDM uses: dict, array, string, integer, real, true/false, data (base64)
 * and date. Not a general plist implementation — it rejects anything outside that subset.
 */

export type PlistValue = string | number | boolean | Date | Uint8Array | PlistValue[] | { [key: string]: PlistValue };

const XML_HEADER = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n';

const escapeXml = (s: string) => s.replace(/[&<>]/g, (c) => (c === "&" ? "&amp;" : c === "<" ? "&lt;" : "&gt;"));

function encodeValue(v: PlistValue, indent: string): string {
  if (typeof v === "string") return `${indent}<string>${escapeXml(v)}</string>`;
  if (typeof v === "boolean") return `${indent}<${v ? "true" : "false"}/>`;
  if (v instanceof Date) return `${indent}<date>${v.toISOString().replace(/\.\d{3}Z$/, "Z")}</date>`;
  if (v instanceof Uint8Array) return `${indent}<data>${Buffer.from(v).toString("base64")}</data>`;
  if (typeof v === "number") return Number.isInteger(v) ? `${indent}<integer>${v}</integer>` : `${indent}<real>${v}</real>`;
  if (Array.isArray(v)) {
    if (v.length === 0) return `${indent}<array/>`;
    return `${indent}<array>\n${v.map((item) => encodeValue(item, indent + "  ")).join("\n")}\n${indent}</array>`;
  }
  const keys = Object.keys(v);
  if (keys.length === 0) return `${indent}<dict/>`;
  const body = keys.map((k) => `${indent}  <key>${escapeXml(k)}</key>\n${encodeValue(v[k]!, indent + "  ")}`).join("\n");
  return `${indent}<dict>\n${body}\n${indent}</dict>`;
}

/** Serialize a value as an XML plist document. */
export function encodePlist(value: PlistValue): string {
  return `${XML_HEADER}${encodeValue(value, "")}\n</plist>\n`;
}

// ─── Parser ─────────────────────────────────────────────────────────────────────────────────────

interface Token {
  name: string;
  closing: boolean;
  selfClosing: boolean;
}

/** Parse an XML plist document. Throws PlistError on anything outside the supported subset. */
export class PlistError extends Error {}

export function parsePlist(xml: string): PlistValue {
  // Strip prolog, DOCTYPE and comments; we only read element content.
  const body = xml.replace(/<\?[\s\S]*?\?>/g, "").replace(/<!DOCTYPE[\s\S]*?>/g, "").replace(/<!--[\s\S]*?-->/g, "");
  let i = 0;
  const len = body.length;

  const next = (): { token?: Token; text?: string } => {
    // Skip whitespace between elements.
    while (i < len && /\s/.test(body[i]!)) i++;
    if (i >= len) return {};
    if (body[i] !== "<") {
      const start = i;
      while (i < len && body[i] !== "<") i++;
      return { text: body.slice(start, i) };
    }
    const end = body.indexOf(">", i);
    if (end === -1) throw new PlistError("Unterminated tag");
    let raw = body.slice(i + 1, end).trim();
    i = end + 1;
    const selfClosing = raw.endsWith("/");
    if (selfClosing) raw = raw.slice(0, -1).trim();
    const closing = raw.startsWith("/");
    const name = (closing ? raw.slice(1) : raw).split(/\s/)[0]!;
    return { token: { name, closing, selfClosing } };
  };

  const readText = (): string => {
    const start = i;
    const close = body.indexOf("<", i);
    if (close === -1) throw new PlistError("Unterminated text");
    i = close;
    return body.slice(start, close);
  };

  const expectClose = (name: string) => {
    const { token } = next();
    if (!token || !token.closing || token.name !== name) throw new PlistError(`Expected </${name}>`);
  };

  const decodeEntities = (s: string) => s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");

  const parseValue = (token: Token): PlistValue => {
    switch (token.name) {
      case "true":
        return true;
      case "false":
        return false;
      case "string": {
        if (token.selfClosing) return "";
        const text = decodeEntities(readText());
        expectClose("string");
        return text;
      }
      case "integer": {
        const text = readText().trim();
        expectClose("integer");
        return Number.parseInt(text, 10);
      }
      case "real": {
        const text = readText().trim();
        expectClose("real");
        return Number.parseFloat(text);
      }
      case "date": {
        const text = readText().trim();
        expectClose("date");
        return new Date(text);
      }
      case "data": {
        if (token.selfClosing) return new Uint8Array();
        const text = readText().replace(/\s+/g, "");
        expectClose("data");
        return new Uint8Array(Buffer.from(text, "base64"));
      }
      case "array": {
        const arr: PlistValue[] = [];
        if (token.selfClosing) return arr;
        for (;;) {
          const { token: t } = next();
          if (!t) throw new PlistError("Unterminated <array>");
          if (t.closing && t.name === "array") return arr;
          arr.push(parseValue(t));
        }
      }
      case "dict": {
        const obj: { [key: string]: PlistValue } = {};
        if (token.selfClosing) return obj;
        for (;;) {
          const { token: t } = next();
          if (!t) throw new PlistError("Unterminated <dict>");
          if (t.closing && t.name === "dict") return obj;
          if (t.name !== "key") throw new PlistError(`Expected <key>, got <${t.name}>`);
          const key = t.selfClosing ? "" : decodeEntities(readText());
          if (!t.selfClosing) expectClose("key");
          const { token: vt } = next();
          if (!vt || vt.closing) throw new PlistError("Missing value for key");
          obj[key] = parseValue(vt);
        }
      }
      default:
        throw new PlistError(`Unsupported plist element <${token.name}>`);
    }
  };

  const { token } = next();
  if (!token) throw new PlistError("Empty plist");
  if (token.name !== "plist") throw new PlistError("Root element must be <plist>");
  if (token.selfClosing) throw new PlistError("Empty <plist>");
  const { token: root } = next();
  if (!root) throw new PlistError("Empty <plist>");
  return parseValue(root);
}

/** Parse a plist and require the root to be a dictionary of string-keyed values. */
export function parsePlistDict(xml: string): Record<string, PlistValue> {
  const v = parsePlist(xml);
  if (typeof v !== "object" || v === null || Array.isArray(v) || v instanceof Date || v instanceof Uint8Array) {
    throw new PlistError("Expected a plist dictionary at the root");
  }
  return v as Record<string, PlistValue>;
}
