import { AttackTechnique, Indicator, type IndicatorType, type Severity } from "@bloody/contracts";
import { z } from "zod";
import { normalizeObservable } from "../core/indicators.js";

/**
 * Indicator records produced by intel connectors (MISP, OpenCTI, STIX bundles, CISA KEV).
 * Shape = contracts `Indicator` without server-assigned ids/tenancy, plus provenance and an
 * explicit scoring explanation. The API upserts on `externalRef` and decides organization
 * scope (TLP:RED / AMBER+STRICT records must stay inside the organization that pulled them).
 */
export const Tlp = z.enum(["clear", "green", "amber", "amber+strict", "red"]);
export type Tlp = z.infer<typeof Tlp>;

export const IndicatorRecord = Indicator.omit({ id: true, tenantId: true, organizationId: true }).extend({
  /** Idempotent upsert key, e.g. "misp:attribute:<uuid>", "opencti:indicator:<standard_id>". */
  externalRef: z.string().min(1).max(500),
  description: z.string().max(4000).nullable(),
  references: z.array(z.string()).max(50),
  attack: z.array(AttackTechnique),
  tlp: Tlp.nullable(),
  /** Revoked upstream: the API must deactivate any stored copy. */
  revoked: z.boolean(),
  /** Human-readable reasons for the confidence and severity values (explainability). */
  scoring: z.array(z.string()),
});
export type IndicatorRecord = z.infer<typeof IndicatorRecord>;

export interface IntelParseResult {
  records: IndicatorRecord[];
  skipped: Array<{ ref: string; reason: string }>;
}

/** Default validity windows per indicator type (days); null = does not decay. */
export const DEFAULT_INDICATOR_TTL_DAYS: Record<IndicatorType, number | null> = {
  ip: 30,
  domain: 90,
  url: 90,
  email: 180,
  ja3: 180,
  user_agent: 180,
  md5: null,
  sha1: null,
  sha256: null,
  cve: null,
};

export function severityFromConfidence(confidence: number): Severity {
  if (confidence >= 85) return "high";
  if (confidence >= 60) return "medium";
  if (confidence >= 30) return "low";
  return "info";
}

export function clampConfidence(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

export function addDays(iso: string, days: number): string {
  return new Date(new Date(iso).getTime() + days * 86_400_000).toISOString();
}

export function parseTlp(value: string | undefined): Tlp | null {
  if (!value) return null;
  const v = value.trim().toLowerCase().replace(/^tlp[:\s-]*/, "");
  if (v === "white" || v === "clear") return "clear";
  if (v === "green") return "green";
  if (v === "amber+strict" || v === "amber-strict") return "amber+strict";
  if (v === "amber") return "amber";
  if (v === "red") return "red";
  return null;
}

/** The most restrictive of several TLP markings. */
export function strictestTlp(values: Array<Tlp | null>): Tlp | null {
  const order: Tlp[] = ["clear", "green", "amber", "amber+strict", "red"];
  let best: Tlp | null = null;
  for (const v of values) if (v && (best === null || order.indexOf(v) > order.indexOf(best))) best = v;
  return best;
}

export interface IndicatorInput {
  type: IndicatorType;
  value: string;
  externalRef: string;
  source: string;
  confidence: number;
  severity?: Severity;
  firstSeenAt: string;
  lastSeenAt: string;
  expiresAt?: string | null;
  threatActor?: string | null;
  malware?: string | null;
  campaign?: string | null;
  tags?: string[];
  description?: string | null;
  references?: string[];
  attack?: AttackTechnique[];
  tlp?: Tlp | null;
  revoked?: boolean;
  scoring?: string[];
  ttlDays?: Partial<Record<IndicatorType, number | null>>;
}

/**
 * Validate + normalize an indicator. Returns a reason string instead of throwing so
 * connectors can report per-item skips.
 */
export function buildIndicatorRecord(input: IndicatorInput): IndicatorRecord | string {
  const value = normalizeObservable(input.type, input.value);
  if (!value) return `invalid ${input.type} value`;
  const confidence = clampConfidence(input.confidence);
  const ttl = input.ttlDays?.[input.type] !== undefined ? input.ttlDays[input.type] : DEFAULT_INDICATOR_TTL_DAYS[input.type];
  const expiresAt = input.expiresAt !== undefined ? input.expiresAt : ttl === null || ttl === undefined ? null : addDays(input.lastSeenAt, ttl);
  const scoring = [...(input.scoring ?? [])];
  if (input.expiresAt === undefined && ttl) scoring.push(`expires ${ttl} days after last sighting (default ${input.type} decay)`);
  const severity = input.severity ?? severityFromConfidence(confidence);
  if (!input.severity) scoring.push(`severity ${severity} derived from confidence ${confidence}`);
  const candidate = {
    type: input.type,
    value,
    confidence,
    severity,
    source: input.source,
    threatActor: input.threatActor ?? null,
    malware: input.malware ?? null,
    campaign: input.campaign ?? null,
    tags: [...new Set((input.tags ?? []).map((t) => t.trim()).filter((t) => t !== "" && t.length <= 200))].slice(0, 50),
    firstSeenAt: input.firstSeenAt,
    lastSeenAt: input.lastSeenAt,
    expiresAt,
    externalRef: input.externalRef,
    description: input.description ? input.description.slice(0, 4000) : null,
    references: (input.references ?? []).slice(0, 50),
    attack: input.attack ?? [],
    tlp: input.tlp ?? null,
    revoked: input.revoked ?? false,
    scoring,
  };
  const parsed = IndicatorRecord.safeParse(candidate);
  if (!parsed.success) return `schema validation failed: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`;
  return parsed.data;
}
