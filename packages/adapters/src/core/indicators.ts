import type { IndicatorType } from "@bloody/contracts";
import { classifyIp, isExternalIp, isIp, splitHostPort } from "../net/ip.js";

/**
 * Observable extraction and normalization shared by event normalizers (indicators attached
 * to canonical events for CTI matching) and intel connectors (indicator records).
 */

export interface Observable {
  type: IndicatorType;
  value: string;
}

/** Undo common defanging: hxxp://, [.] (.) {.} [dot], [:]//, [@]. */
export function refang(value: string): string {
  return value
    .trim()
    .replace(/^hxxp/i, "http")
    .replace(/^fxp/i, "ftp")
    .replace(/\[(\.|dot)\]|\((\.|dot)\)|\{(\.|dot)\}/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[(@|at)\]/gi, "@");
}

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/i;
const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]{1,64}@[^\s@<>()[\]\\,;:"]{1,253}$/;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const HASH_TYPES: Record<number, IndicatorType> = { 32: "md5", 40: "sha1", 64: "sha256" };

/** Suffixes of organization-internal names; never internet indicators. */
const NON_PUBLIC_SUFFIXES = [".local", ".localdomain", ".internal", ".lan", ".home", ".corp", ".intranet", ".arpa", ".localhost"];

export function isDomain(value: string): boolean {
  return DOMAIN_RE.test(value) && !isIp(value);
}

export function isPublicDomain(value: string): boolean {
  const v = value.toLowerCase();
  return isDomain(v) && !NON_PUBLIC_SUFFIXES.some((s) => v.endsWith(s));
}

export function hashType(value: string): IndicatorType | undefined {
  const v = value.trim();
  if (!/^[0-9a-f]+$/i.test(v)) return undefined;
  return HASH_TYPES[v.length];
}

export function isCve(value: string): boolean {
  return CVE_RE.test(value.trim());
}

/**
 * Normalize an observable value for its type; undefined when it is not valid for the type.
 * Lower-cases case-insensitive types, strips ports from IPs, upper-cases CVE ids.
 */
export function normalizeObservable(type: IndicatorType, raw: string): string | undefined {
  const v = refang(raw);
  if (v === "") return undefined;
  switch (type) {
    case "ip": {
      const { host } = splitHostPort(v);
      return isIp(host) ? host.toLowerCase() : undefined;
    }
    case "domain": {
      const d = v.toLowerCase().replace(/\.$/, "");
      return isDomain(d) ? d : undefined;
    }
    case "url": {
      try {
        const u = new URL(v);
        return u.protocol === "http:" || u.protocol === "https:" || u.protocol === "ftp:" ? u.toString() : undefined;
      } catch {
        return undefined;
      }
    }
    case "md5":
    case "sha1":
    case "sha256":
      return hashType(v) === type ? v.toLowerCase() : undefined;
    case "email":
      return EMAIL_RE.test(v) ? v.toLowerCase() : undefined;
    case "cve":
      return isCve(v) ? v.toUpperCase() : undefined;
    case "ja3":
      return /^[0-9a-f]{32}$/i.test(v) ? v.toLowerCase() : undefined;
    case "user_agent":
      return v.length >= 4 && v.length <= 1024 ? v : undefined;
  }
}

/**
 * Accumulates observables for one event, applying the "worth matching" policy:
 * internal IPs and internal domains are skipped (CTI never matches RFC 1918 space and they
 * would only produce noise), duplicates removed.
 */
export class ObservableSet {
  private readonly items = new Map<string, Observable>();

  add(type: IndicatorType, value: string | undefined | null): this {
    if (value === undefined || value === null) return this;
    const v = normalizeObservable(type, value);
    if (!v) return this;
    if (type === "ip" && !isExternalIp(v)) return this;
    if (type === "domain" && !isPublicDomain(v)) return this;
    this.items.set(`${type}:${v}`, { type, value: v });
    return this;
  }

  /** Add an IP or a domain, whichever the value is. */
  addHost(value: string | undefined | null): this {
    if (!value) return this;
    const { host } = splitHostPort(value);
    return classifyIp(host) ? this.add("ip", host) : this.add("domain", host);
  }

  /** Add a hash of whatever type its length implies. */
  addHash(value: string | undefined | null): this {
    if (!value) return this;
    const t = hashType(value);
    return t ? this.add(t, value) : this;
  }

  addAll(type: IndicatorType, values: Iterable<string | undefined | null>): this {
    for (const v of values) this.add(type, v);
    return this;
  }

  get size(): number {
    return this.items.size;
  }

  toArray(): Observable[] {
    return [...this.items.values()];
  }
}

/**
 * Parse Sysmon/Wazuh style hash lists: "SHA1=..,MD5=..,SHA256=..,IMPHASH=.." or a bare hash.
 */
export function parseHashList(value: string | undefined): { md5?: string; sha1?: string; sha256?: string } {
  const out: { md5?: string; sha1?: string; sha256?: string } = {};
  if (!value) return out;
  for (const part of value.split(/[,;\s]+/)) {
    const eq = part.indexOf("=");
    const algo = eq > 0 ? part.slice(0, eq).toUpperCase() : "";
    const hash = (eq > 0 ? part.slice(eq + 1) : part).trim().toLowerCase();
    const t = hashType(hash);
    if (!t) continue;
    if ((algo === "" || algo === "MD5") && t === "md5") out.md5 = hash;
    else if ((algo === "" || algo === "SHA1") && t === "sha1") out.sha1 = hash;
    else if ((algo === "" || algo === "SHA256") && t === "sha256") out.sha256 = hash;
  }
  return out;
}
