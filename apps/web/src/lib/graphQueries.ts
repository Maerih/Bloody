import type { GraphNode, NodeKind } from "@bloody/contracts";
import type { AiContextKind } from "../api/types";
import { ASSET_NODE_KINDS, IDENTITY_NODE_KINDS } from "../components/graph/nodeKinds";
import { pivotQuery } from "../features/events/eventFormat";

/**
 * Pivot helpers from a Security Graph node to the rest of the platform: event searches, intel
 * lookups, response-action targets and AI context. They only use what the node carries
 * (kind, key, label, props.assetId / props.identityId…) and never guess identifiers.
 */

const str = (v: unknown): string | null => (typeof v === "string" && v.length > 0 ? v : null);

export function nodeValue(node: GraphNode): string {
  return node.key || node.label || node.id;
}

/** Inventory asset id behind an asset-like node, when the graph links one. */
export function assetIdForNode(node: GraphNode): string | null {
  if (!(ASSET_NODE_KINDS as string[]).includes(node.kind)) return null;
  return str(node.props?.assetId);
}

/** Identity id behind an identity-like node, when the graph links one. */
export function identityIdForNode(node: GraphNode): string | null {
  if (!(IDENTITY_NODE_KINDS as string[]).includes(node.kind)) return null;
  return str(node.props?.identityId);
}

export function isEndpointNode(node: GraphNode): boolean {
  return node.kind === "endpoint" || node.kind === "server" || node.kind === "cloud_asset";
}

/** Indicator kind/value for intel lookups and block actions. */
export function indicatorForNode(node: GraphNode): { type: "ip" | "domain" | "url" | "sha256" | "md5" | "sha1"; value: string } | null {
  const v = nodeValue(node);
  switch (node.kind) {
    case "ip":
      return { type: "ip", value: v };
    case "domain":
      return { type: "domain", value: v };
    case "url":
      return { type: "url", value: v };
    case "hash": {
      const len = v.length;
      return { type: len === 32 ? "md5" : len === 40 ? "sha1" : "sha256", value: v };
    }
    case "indicator": {
      const t = str(node.props?.type);
      if (t === "ip" || t === "domain" || t === "url" || t === "sha256" || t === "md5" || t === "sha1") return { type: t, value: str(node.props?.value) ?? v };
      return null;
    }
    default:
      return null;
  }
}

/** Bloody query that finds the events mentioning this node (null when no meaningful field). */
export function eventQueryForNode(node: GraphNode): string | null {
  const v = nodeValue(node);
  const assetId = assetIdForNode(node);
  const kind: NodeKind = node.kind;
  switch (kind) {
    case "endpoint":
    case "server":
    case "cloud_asset":
    case "container":
    case "data_store":
    case "application":
      return assetId ? pivotQuery("asset.id", assetId) : pivotQuery("asset.hostname", node.label || v);
    case "user":
      return pivotQuery("user.name", node.label || v);
    case "identity":
    case "service_account":
      return identityIdForNode(node) ? pivotQuery("identity.id", identityIdForNode(node)!) : pivotQuery("identity.principal", v);
    case "process":
      return pivotQuery("process.name", node.label || v);
    case "file":
      return pivotQuery("file.path", v);
    case "hash":
      return `${pivotQuery("process.hashSha256", v)} OR ${pivotQuery("file.sha256", v)}`;
    case "ip":
      return `${pivotQuery("network.dstIp", v)} OR ${pivotQuery("network.srcIp", v)} OR ${pivotQuery("identity.sourceIp", v)}`;
    case "domain":
      return `${pivotQuery("network.dnsQuery", v)} OR ${pivotQuery("network.httpHost", v)} OR ${pivotQuery("network.tlsSni", v)}`;
    case "url":
      return pivotQuery("network.httpUrl", v);
    case "indicator":
      return pivotQuery("indicators.value", str(node.props?.value) ?? v);
    case "technique":
      return pivotQuery("attack.id", v);
    case "vulnerability":
      return /^CVE-\d{4}-\d+$/i.test(v) ? pivotQuery("indicators.value", v.toUpperCase()) : null;
    default:
      return null;
  }
}

/** AI SOC context for "Ask AI" on a node. */
export function aiContextForNode(node: GraphNode): { kind: AiContextKind; id: string } | null {
  const assetId = assetIdForNode(node);
  if (assetId) return { kind: "asset", id: assetId };
  const identityId = identityIdForNode(node);
  if (identityId) return { kind: "identity", id: identityId };
  if (node.kind === "incident") return { kind: "incident", id: str(node.props?.incidentId) ?? node.key };
  if (node.kind === "investigation") return { kind: "investigation", id: str(node.props?.investigationId) ?? node.key };
  const ind = indicatorForNode(node);
  if (ind) return { kind: "indicator", id: str(node.props?.indicatorId) ?? ind.value };
  return null;
}

export function aiHref(ctx: { kind: AiContextKind; id: string }): string {
  return `/ai?context=${encodeURIComponent(`${ctx.kind}:${ctx.id}`)}`;
}

/** Display rows for a node's properties (scalars only; long values truncated by the caller). */
export function nodePropRows(node: GraphNode): { key: string; value: string }[] {
  return Object.entries(node.props ?? {})
    .filter(([, v]) => v !== null && v !== undefined && (typeof v !== "object" || Array.isArray(v)))
    .map(([key, v]) => ({ key, value: Array.isArray(v) ? v.map(String).join(", ") : String(v) }))
    .sort((a, b) => a.key.localeCompare(b.key));
}
