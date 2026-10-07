import type { Alert, AttackPath, CanonicalEvent, GraphEdge, GraphNode, Identity, Incident, Indicator, RiskAssessment, Subgraph, Vulnerability } from "@bloody/contracts";
import { truncate } from "../util/json.js";

/**
 * Token-efficient, model-facing projections of Bloody entities. They keep identifiers (so the
 * model can cite and pivot), drop bulky/raw fields (provenance.raw is NEVER sent to a model) and
 * bound free text.
 */

export function compactIncident(i: Incident): Record<string, unknown> {
  return {
    id: i.id,
    number: i.number,
    title: i.title,
    summary: i.summary ? truncate(i.summary, 1500) : null,
    severity: i.severity,
    status: i.status,
    riskScore: i.riskScore,
    attack: i.attack.map((t) => t.id + (t.name ? ` ${t.name}` : "")),
    alertCount: i.alertCount,
    assetIds: i.assetIds.slice(0, 25),
    identityIds: i.identityIds.slice(0, 25),
    detectedAt: i.detectedAt,
    acknowledgedAt: i.acknowledgedAt,
    containedAt: i.containedAt,
    closedAt: i.closedAt,
  };
}

export function compactAlert(a: Alert): Record<string, unknown> {
  return {
    id: a.id,
    title: a.title,
    severity: a.severity,
    status: a.status,
    source: a.source,
    ruleId: a.ruleId,
    assetId: a.assetId,
    identityId: a.identityId,
    incidentId: a.incidentId,
    attack: a.attack.map((t) => t.id),
    confidence: a.confidence,
    riskScore: a.riskScore,
    firstSeenAt: a.firstSeenAt,
    lastSeenAt: a.lastSeenAt,
  };
}

export function compactEvent(e: CanonicalEvent): Record<string, unknown> {
  const out: Record<string, unknown> = {
    id: e.id,
    timestamp: e.timestamp,
    category: e.category,
    eventType: e.eventType,
    source: e.source.product,
    severity: e.severity,
  };
  if (e.action) out.action = e.action;
  if (e.outcome) out.outcome = e.outcome;
  if (e.message) out.message = truncate(e.message, 500);
  if (e.asset) out.asset = { id: e.asset.id, hostname: e.asset.hostname, ip: e.asset.ip?.slice(0, 4) };
  if (e.user) out.user = e.user;
  if (e.identity) out.identity = { principal: e.identity.principal, provider: e.identity.provider, sourceIp: e.identity.sourceIp, outcome: e.identity.outcome, mfa: e.identity.mfa, geo: e.identity.geo?.country };
  if (e.process) {
    out.process = {
      name: e.process.name,
      pid: e.process.pid,
      commandLine: e.process.commandLine ? truncate(e.process.commandLine, 600) : undefined,
      user: e.process.user,
      sha256: e.process.hashSha256,
      parent: e.process.parent ? { name: e.process.parent.name, commandLine: e.process.parent.commandLine ? truncate(e.process.parent.commandLine, 300) : undefined } : undefined,
    };
  }
  if (e.file) out.file = { path: e.file.path, action: e.file.action, sha256: e.file.sha256 };
  if (e.network) out.network = e.network;
  if (e.cloudResource) out.cloudResource = e.cloudResource;
  if (e.indicators.length) out.indicators = e.indicators.slice(0, 10);
  if (e.detection) out.detection = e.detection;
  if (e.attack.length) out.attack = e.attack.map((t) => t.id);
  if (e.risk !== undefined) out.risk = e.risk;
  return out;
}

export function compactIdentity(i: Identity): Record<string, unknown> {
  return {
    id: i.id,
    kind: i.kind,
    provider: i.provider,
    principal: i.principal,
    displayName: i.displayName,
    privileged: i.privileged,
    mfaEnabled: i.mfaEnabled,
    lastActivityAt: i.lastActivityAt,
    riskScore: i.riskScore,
  };
}

export function compactVulnerability(v: Vulnerability): Record<string, unknown> {
  return {
    id: v.id,
    assetId: v.assetId,
    cve: v.cve,
    title: truncate(v.title, 200),
    severity: v.severity,
    cvss: v.cvss,
    epss: v.epss,
    knownExploited: v.knownExploited,
    status: v.status,
    patchAvailable: v.patchAvailable,
    slaDueAt: v.slaDueAt,
    riskScore: v.riskScore,
  };
}

export function compactIndicator(i: Indicator): Record<string, unknown> {
  return {
    id: i.id,
    type: i.type,
    value: i.value,
    confidence: i.confidence,
    severity: i.severity,
    source: i.source,
    threatActor: i.threatActor,
    malware: i.malware,
    campaign: i.campaign,
    tags: i.tags.slice(0, 10),
    firstSeenAt: i.firstSeenAt,
    lastSeenAt: i.lastSeenAt,
    expiresAt: i.expiresAt,
  };
}

/** Risk assessment with factors ordered by absolute contribution (explainability first). */
export function compactRisk(r: RiskAssessment, maxFactors = 8): Record<string, unknown> {
  const factors = [...r.factors].sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
  return {
    score: r.score,
    severity: r.severity,
    likelihood: r.likelihood,
    impact: r.impact,
    summary: r.summary,
    modelVersion: r.modelVersion,
    topFactors: factors.slice(0, maxFactors).map((f) => ({ key: f.key, label: f.label, contribution: Math.round(f.contribution * 10) / 10, value: f.value, explanation: f.explanation })),
    omittedFactors: Math.max(0, factors.length - maxFactors),
  };
}

function compactNode(n: GraphNode): Record<string, unknown> {
  return { id: n.id, kind: n.kind, label: n.label, key: n.key };
}

function compactEdge(e: GraphEdge): Record<string, unknown> {
  return { id: e.id, kind: e.kind, from: e.from, to: e.to };
}

export function compactSubgraph(g: Subgraph, maxNodes = 120, maxEdges = 200): Record<string, unknown> {
  const byKind: Record<string, number> = {};
  for (const n of g.nodes) byKind[n.kind] = (byKind[n.kind] ?? 0) + 1;
  return {
    nodeCount: g.nodes.length,
    edgeCount: g.edges.length,
    nodesByKind: byKind,
    nodes: g.nodes.slice(0, maxNodes).map(compactNode),
    edges: g.edges.slice(0, maxEdges).map(compactEdge),
    truncated: g.nodes.length > maxNodes || g.edges.length > maxEdges,
  };
}

export function compactAttackPath(p: AttackPath): Record<string, unknown> {
  return {
    id: p.id,
    entry: compactNode(p.entry),
    target: compactNode(p.target),
    hops: p.edges.map((e) => {
      const from = p.nodes.find((n) => n.id === e.from);
      const to = p.nodes.find((n) => n.id === e.to);
      return `${from?.label ?? e.from} -[${e.kind}]-> ${to?.label ?? e.to}`;
    }),
    risk: compactRisk(p.risk, 5),
    remediations: p.remediations.slice(0, 5),
  };
}
