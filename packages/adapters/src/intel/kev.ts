import { z } from "zod";
import { isCve } from "../core/indicators.js";
import { strArr } from "../core/json.js";
import { toIso } from "../core/time.js";
import { EngineClient, type EngineClientOptions } from "../http/client.js";
import { buildIndicatorRecord, type IntelParseResult } from "./types.js";

/**
 * CISA Known Exploited Vulnerabilities catalog (public domain, key-less JSON feed).
 * Used to flag vulnerabilities as known-exploited, set remediation due dates and raise
 * `vulnerability.kev_detected` automation signals.
 */
export const CISA_KEV_FEED = {
  origin: "https://www.cisa.gov",
  path: "/sites/default/files/feeds/known_exploited_vulnerabilities.json",
} as const;

const KevVulnerability = z
  .object({
    cveID: z.string(),
    vendorProject: z.string().optional().default(""),
    product: z.string().optional().default(""),
    vulnerabilityName: z.string().optional().default(""),
    dateAdded: z.string().optional().default(""),
    shortDescription: z.string().optional().default(""),
    requiredAction: z.string().optional().default(""),
    dueDate: z.string().optional().default(""),
    knownRansomwareCampaignUse: z.string().optional().default("Unknown"),
    notes: z.string().optional().default(""),
    cwes: z.array(z.string()).optional().default([]),
  })
  .passthrough();

export const KevFeedSchema = z
  .object({
    title: z.string().optional(),
    catalogVersion: z.string().optional(),
    dateReleased: z.string().optional(),
    count: z.number().optional(),
    vulnerabilities: z.array(z.unknown()),
  })
  .passthrough();

export interface KevEntry {
  cve: string;
  vendorProject: string;
  product: string;
  name: string;
  dateAdded: string | null;
  shortDescription: string;
  requiredAction: string;
  /** Federal remediation due date (ISO date-time, end of day UTC). */
  dueDate: string | null;
  knownRansomwareCampaignUse: boolean;
  notes: string;
  cwes: string[];
}

function dateOnlyToIso(value: string, endOfDay = false): string | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return toIso(value) ?? null;
  return `${value}T${endOfDay ? "23:59:59.000" : "00:00:00.000"}Z`;
}

export class KevCatalog {
  private readonly byCve: Map<string, KevEntry>;

  private constructor(
    entries: KevEntry[],
    readonly catalogVersion: string | null,
    readonly dateReleased: string | null,
    readonly invalid: number,
  ) {
    this.byCve = new Map(entries.map((e) => [e.cve, e]));
  }

  static parse(input: unknown): KevCatalog {
    const json = typeof input === "string" ? (JSON.parse(input) as unknown) : input;
    const feed = KevFeedSchema.parse(json);
    const entries: KevEntry[] = [];
    let invalid = 0;
    for (const raw of feed.vulnerabilities) {
      const v = KevVulnerability.safeParse(raw);
      if (!v.success || !isCve(v.data.cveID)) {
        invalid++;
        continue;
      }
      const d = v.data;
      entries.push({
        cve: d.cveID.toUpperCase(),
        vendorProject: d.vendorProject,
        product: d.product,
        name: d.vulnerabilityName,
        dateAdded: dateOnlyToIso(d.dateAdded),
        shortDescription: d.shortDescription,
        requiredAction: d.requiredAction,
        dueDate: dateOnlyToIso(d.dueDate, true),
        knownRansomwareCampaignUse: d.knownRansomwareCampaignUse.toLowerCase() === "known",
        notes: d.notes,
        cwes: strArr(d.cwes),
      });
    }
    return new KevCatalog(entries, feed.catalogVersion ?? null, feed.dateReleased ? toIso(feed.dateReleased) ?? null : null, invalid);
  }

  get size(): number {
    return this.byCve.size;
  }

  has(cve: string): boolean {
    return this.byCve.has(cve.trim().toUpperCase());
  }

  get(cve: string): KevEntry | undefined {
    return this.byCve.get(cve.trim().toUpperCase());
  }

  entries(): KevEntry[] {
    return [...this.byCve.values()];
  }

  /** KEV entries as `cve` indicator records (critical when ransomware use is known). */
  toIndicators(now: string): IntelParseResult {
    const out: IntelParseResult = { records: [], skipped: [] };
    for (const e of this.byCve.values()) {
      const added = e.dateAdded ?? now;
      const r = buildIndicatorRecord({
        type: "cve",
        value: e.cve,
        externalRef: `cisa_kev:${e.cve}`,
        source: "cisa_kev",
        confidence: 100,
        severity: e.knownRansomwareCampaignUse ? "critical" : "high",
        firstSeenAt: added,
        lastSeenAt: this.dateReleased ?? now,
        expiresAt: null,
        tags: ["known-exploited", ...(e.knownRansomwareCampaignUse ? ["ransomware"] : []), ...e.cwes.map((c) => `cwe:${c}`)],
        description: `${e.vendorProject} ${e.product}: ${e.name}. ${e.shortDescription}`.trim(),
        references: [],
        scoring: [
          "confidence 100: listed in the CISA Known Exploited Vulnerabilities catalog (exploitation observed in the wild)",
          e.knownRansomwareCampaignUse ? "severity critical: known use in ransomware campaigns" : "severity high: known exploited",
        ],
      });
      if (typeof r === "string") out.skipped.push({ ref: e.cve, reason: r });
      else out.records.push(r);
    }
    return out;
  }
}

export function createKevClient(opts: Omit<EngineClientOptions, "engine" | "baseUrl"> & { baseUrl?: string } = {}): EngineClient {
  return new EngineClient({ ...opts, engine: "cisa_kev", baseUrl: opts.baseUrl ?? CISA_KEV_FEED.origin, timeoutMs: opts.timeoutMs ?? 60_000 });
}

export async function fetchKevCatalog(client: EngineClient, path: string = CISA_KEV_FEED.path): Promise<KevCatalog> {
  const res = await client.get<unknown>(path);
  return KevCatalog.parse(res.data);
}
