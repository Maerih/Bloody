import type { AutorunKind, FootholdVerdict } from "./footholds.js";
import type { HardeningSeverity, HardeningStatus } from "./attack-reduction.js";
import type { PatchEndpoint } from "./patching.js";

/**
 * Everything SCIAT knows about one computer beyond its inventory: the agents on it, isolation,
 * patching, hardening, persistence, remote-access tools and a timeline of what happened to it.
 * Shown on the computer's page and rendered as the single-computer report.
 */

export const ENDPOINT_ACTIVITY_KINDS = ["agent", "isolation", "response", "alert", "incident", "persistence", "app_control", "change"] as const;
export type EndpointActivityKind = (typeof ENDPOINT_ACTIVITY_KINDS)[number];

export const ENDPOINT_ACTIVITY_LABELS: Record<EndpointActivityKind, string> = {
  agent: "Agent",
  isolation: "Isolation",
  response: "Response",
  alert: "Alert",
  incident: "Incident",
  persistence: "Persistence",
  app_control: "App Control",
  change: "Change",
};

export interface EndpointActivity {
  at: string;
  kind: EndpointActivityKind;
  title: string;
  detail: string | null;
  /** Person or system that did it ("SCIAT Agent", a user's name…). */
  actor: string | null;
  outcome: "success" | "failure" | "pending" | null;
  severity: "critical" | "high" | "medium" | "low" | "info" | null;
}

export interface EndpointDossierAgent {
  id: string;
  engine: string;
  version: string | null;
  platform: string | null;
  status: string;
  isolation: { mode: "lan" | "full"; since: string; source: "platform" | "endpoint" } | null;
  enrolledAt: string | null;
  lastCheckinAt: string | null;
}

export interface EndpointDossier {
  assetId: string;
  organizationId: string;
  hostname: string;
  generatedAt: string;
  agents: EndpointDossierAgent[];
  /** Patch status from the SCIAT Agent (null when not reported yet). */
  patching: PatchEndpoint | null;
  hardening: {
    score: number | null;
    collectedAt: string;
    checks: Array<{ key: string; title: string; severity: HardeningSeverity; status: HardeningStatus; detail: string | null; accepted: boolean; fix: string }>;
  } | null;
  footholds: Array<{
    name: string;
    kind: AutorunKind;
    location: string;
    command: string | null;
    level: "high" | "medium" | "low";
    score: number;
    reasons: string[];
    verdict: FootholdVerdict | null;
    isNew: boolean;
    firstSeen: string;
  }>;
  remoteAccess: Array<{ name: string; vendor: string; approved: boolean; evidence: string[] }>;
  /** Newest first; capped (see `activityTruncated`). */
  activity: EndpointActivity[];
  activityTruncated: boolean;
  activitySince: string;
}
