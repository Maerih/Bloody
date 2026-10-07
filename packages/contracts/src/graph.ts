import { z } from "zod";

/** Node kinds of the Security Graph. */
export const NODE_KINDS = [
  "organization",
  "user",
  "identity",
  "group",
  "service_account",
  "endpoint",
  "server",
  "cloud_asset",
  "application",
  "container",
  "k8s_resource",
  "process",
  "file",
  "hash",
  "ip",
  "domain",
  "url",
  "certificate",
  "vulnerability",
  "credential",
  "session",
  "oauth_app",
  "saas_app",
  "threat_actor",
  "malware",
  "campaign",
  "indicator",
  "incident",
  "investigation",
  "technique",
  "control",
  "policy",
  "internet",
  "data_store",
] as const;
export const NodeKind = z.enum(NODE_KINDS);
export type NodeKind = z.infer<typeof NodeKind>;

/** Directed edge kinds. `from -[kind]-> to`. */
export const EDGE_KINDS = [
  "member_of",
  "has_access_to",
  "admin_of",
  "logged_into",
  "owns",
  "runs_on",
  "spawned",
  "wrote",
  "executed",
  "has_hash",
  "connected_to",
  "resolves_to",
  "exposes",
  "has_vulnerability",
  "can_reach",
  "authenticates_as",
  "stores_credential_for",
  "attributed_to",
  "uses",
  "observed_on",
  "indicates",
  "involves",
  "mitigated_by",
  "contains",
  "trusts",
] as const;
export const EdgeKind = z.enum(EDGE_KINDS);
export type EdgeKind = z.infer<typeof EdgeKind>;

export const GraphNode = z.object({
  id: z.string(),
  kind: NodeKind,
  /** Natural key, unique per (tenant, org, kind): hostname, sha256, ip, CVE, principal… */
  key: z.string(),
  label: z.string(),
  organizationId: z.string().uuid().nullable(),
  props: z.record(z.unknown()).default({}),
});
export type GraphNode = z.infer<typeof GraphNode>;

export const GraphEdge = z.object({
  id: z.string(),
  kind: EdgeKind,
  from: z.string(),
  to: z.string(),
  props: z.record(z.unknown()).default({}),
});
export type GraphEdge = z.infer<typeof GraphEdge>;

export interface Subgraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/** One explained contribution to a score. Every score in Bloody carries these. */
export const RiskFactor = z.object({
  key: z.string(),
  label: z.string(),
  /** Normalized 0..1 signal value. */
  value: z.number().min(0).max(1),
  /** Weight applied in the model. */
  weight: z.number(),
  /** Points contributed to the final 0..100 score (may be negative for compensating controls). */
  contribution: z.number(),
  explanation: z.string(),
});
export type RiskFactor = z.infer<typeof RiskFactor>;

export const RiskAssessment = z.object({
  score: z.number().min(0).max(100),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  likelihood: z.number().min(0).max(1),
  impact: z.number().min(0).max(1),
  factors: z.array(RiskFactor),
  summary: z.string(),
  modelVersion: z.string(),
});
export type RiskAssessment = z.infer<typeof RiskAssessment>;

export const AttackPath = z.object({
  id: z.string(),
  nodes: z.array(GraphNode),
  edges: z.array(GraphEdge),
  target: GraphNode,
  entry: GraphNode,
  risk: RiskAssessment,
  /** Ordered remediation suggestions; the first breaks the most paths. */
  remediations: z.array(z.object({ nodeId: z.string().optional(), edgeId: z.string().optional(), action: z.string(), pathsBroken: z.number().int() })),
});
export type AttackPath = z.infer<typeof AttackPath>;
