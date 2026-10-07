import { getEventField, type CanonicalEvent, type Indicator, type IndicatorType, type Severity } from "@bloody/contracts";
import { normalizeDomain, normalizeIndicatorValue, normalizeUrl, parentDomains } from "../entities/keys.js";
import { systemClock, type Clock } from "../util/clock.js";
import { cidrContains, isNonPublicIp, normalizeIp, parseCidr, type Cidr } from "../util/ip.js";

/** Indicator as held by the matcher (contract `Indicator` subset, value normalized). */
export interface IndicatorRecord {
  id?: string;
  tenantId: string;
  /** null = tenant-wide (e.g. MSSP feed shared by every customer organization). */
  organizationId: string | null;
  type: IndicatorType;
  value: string;
  confidence: number;
  severity: Severity;
  source: string;
  threatActor?: string | null;
  malware?: string | null;
  campaign?: string | null;
  expiresAt?: string | null;
}

/** Synchronous lookup used on the hot detection path (hydrate from the DB / cache). */
export interface IndicatorProvider {
  lookup(tenantId: string, organizationId: string, type: IndicatorType, value: string): IndicatorRecord[];
}

/**
 * Tenant-partitioned in-memory indicator index: exact-value hash lookup per type plus a CIDR
 * list for network-range indicators. Org-scoped indicators only match their organization;
 * tenant-wide ones match every organization of the tenant; never across tenants. Expired
 * indicators are ignored at lookup time (injected clock).
 */
export class IndicatorSet implements IndicatorProvider {
  private readonly exact = new Map<string, Map<string, IndicatorRecord[]>>();
  private readonly cidrs = new Map<string, Array<{ cidr: Cidr; record: IndicatorRecord }>>();
  private readonly clock: Clock;
  private count = 0;

  constructor(options: { clock?: Clock } = {}) {
    this.clock = options.clock ?? systemClock;
  }

  get size(): number {
    return this.count;
  }

  /** Add a contract `Indicator` (or record). Returns false when the value is invalid for its type. */
  add(indicator: Indicator | IndicatorRecord): boolean {
    const value = normalizeIndicatorValue(indicator.type, indicator.value);
    if (value === null) return false;
    const record: IndicatorRecord = {
      ...(indicator.id ? { id: indicator.id } : {}),
      tenantId: indicator.tenantId,
      organizationId: indicator.organizationId,
      type: indicator.type,
      value,
      confidence: indicator.confidence,
      severity: indicator.severity,
      source: indicator.source,
      threatActor: indicator.threatActor ?? null,
      malware: indicator.malware ?? null,
      campaign: indicator.campaign ?? null,
      expiresAt: indicator.expiresAt ?? null,
    };
    if (record.type === "ip" && value.includes("/")) {
      const cidr = parseCidr(value);
      if (!cidr) return false;
      const list = this.cidrs.get(record.tenantId) ?? [];
      list.push({ cidr, record });
      this.cidrs.set(record.tenantId, list);
    } else {
      const byKey = this.exact.get(record.tenantId) ?? new Map<string, IndicatorRecord[]>();
      const key = `${record.type}:${value}`;
      const list = (byKey.get(key) ?? []).filter((r) => !(r.organizationId === record.organizationId && r.source === record.source));
      list.push(record);
      byKey.set(key, list);
      this.exact.set(record.tenantId, byKey);
    }
    this.count++;
    return true;
  }

  addMany(indicators: Iterable<Indicator | IndicatorRecord>): number {
    let n = 0;
    for (const i of indicators) if (this.add(i)) n++;
    return n;
  }

  lookup(tenantId: string, organizationId: string, type: IndicatorType, value: string): IndicatorRecord[] {
    const now = this.clock.now();
    const live = (r: IndicatorRecord) => (r.organizationId === null || r.organizationId === organizationId) && (!r.expiresAt || Date.parse(r.expiresAt) > now);
    const out = (this.exact.get(tenantId)?.get(`${type}:${value}`) ?? []).filter(live);
    if (type === "ip") for (const { cidr, record } of this.cidrs.get(tenantId) ?? []) if (live(record) && cidrContains(cidr, value)) out.push(record);
    return out;
  }
}

export interface Observable {
  type: IndicatorType;
  value: string;
  field: string;
}

/** Observables of an event that can be matched against indicators, normalized and de-duplicated. */
export function extractObservables(event: CanonicalEvent, options: { ignoreNonPublicIps?: boolean } = {}): Observable[] {
  const out = new Map<string, Observable>();
  const add = (type: IndicatorType, raw: unknown, field: string) => {
    if (typeof raw !== "string" || raw.length === 0) return;
    let value: string | null;
    if (type === "ip") value = normalizeIp(raw);
    else if (type === "domain") value = normalizeDomain(raw);
    else if (type === "url") value = normalizeUrl(raw);
    else value = normalizeIndicatorValue(type, raw);
    if (value === null) return;
    if (type === "ip" && (options.ignoreNonPublicIps ?? true) && isNonPublicIp(value)) return;
    const k = `${type}:${value}`;
    if (!out.has(k)) out.set(k, { type, value, field });
  };
  for (const ind of event.indicators ?? []) add(ind.type, ind.value, "indicators");
  add("ip", event.network?.dstIp, "network.dstIp");
  add("ip", event.network?.srcIp, "network.srcIp");
  add("ip", event.identity?.sourceIp, "identity.sourceIp");
  add("domain", event.network?.dnsQuery, "network.dnsQuery");
  add("domain", event.network?.httpHost, "network.httpHost");
  add("domain", event.network?.tlsSni, "network.tlsSni");
  add("url", event.network?.httpUrl, "network.httpUrl");
  add("sha256", event.process?.hashSha256, "process.hashSha256");
  add("sha256", event.file?.sha256, "file.sha256");
  add("md5", event.file?.md5, "file.md5");
  add("ja3", event.network?.ja3, "network.ja3");
  add("email", event.user?.email, "user.email");
  add("user_agent", getEventField(event, "labels.userAgent"), "labels.userAgent");
  return [...out.values()];
}

/** Lookup candidates for one observable (domains also try parent domains when enabled). */
export function lookupCandidates(o: Observable, matchSubdomains: boolean): string[] {
  if (o.type === "domain" && matchSubdomains) return [o.value, ...parentDomains(o.value)];
  return [o.value];
}
