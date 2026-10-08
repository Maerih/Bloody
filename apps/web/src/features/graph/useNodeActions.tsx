import type { GraphNode, ResponseActionKey } from "@bloody/contracts";
import { Ban, Crosshair, EyeOff, Fingerprint, Lock, Network, Search, Server, Sparkles, Target } from "lucide-react";
import { useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useSession } from "../../app/session";
import type { NodeAction } from "../../components/graph/GraphNodeMenu";
import { hrefForEntity } from "../../lib/entityLinks";
import { aiContextForNode, aiHref, assetIdForNode, eventQueryForNode, identityIdForNode, indicatorForNode, isEndpointNode, nodeValue } from "../../lib/graphQueries";
import { searchHref } from "../events/eventFormat";
import { RequestActionDialog, type ActionTargetKind } from "../response/RequestActionDialog";

interface PendingAction {
  node: GraphNode;
  organizationId: string;
  action: ResponseActionKey;
  targets: Partial<Record<ActionTargetKind, { id: string; label?: string }[]>>;
  indicator?: string;
}

export interface NodeActionOptions {
  /** Expand the node's neighbors in place (explorer / investigation graph). */
  onExpand?: (node: GraphNode) => void;
  /** Remove the node from the canvas. */
  onHide?: (node: GraphNode) => void;
  /** Re-centre the explorer on this node. */
  onFocus?: (node: GraphNode) => void;
  /** Incident the actions are taken for (response actions get linked to it). */
  incidentId?: string;
}

/**
 * Contextual actions for a Security Graph node, shared by the explorer, the investigation
 * graph and attack paths: open asset / identity, search events, intel lookup, ask AI, and
 * approval-gated response requests (isolate endpoint, block IP / domain, disable identity).
 */
export function useNodeActions(options: NodeActionOptions = {}): { actionsFor: (node: GraphNode) => NodeAction[]; dialog: ReactNode } {
  const session = useSession();
  const navigate = useNavigate();
  const [pending, setPending] = useState<PendingAction | null>(null);

  const actionsFor = (node: GraphNode): NodeAction[] => {
    const out: NodeAction[] = [];
    const orgId = node.organizationId ?? session.organizationId;
    const assetId = assetIdForNode(node);
    const identityId = identityIdForNode(node);
    const indicator = indicatorForNode(node);
    const query = eventQueryForNode(node);
    const canRequest = orgId !== null && session.can("response:request", orgId);

    if (options.onExpand) out.push({ key: "expand", label: "Expand neighbors", icon: Network, onSelect: () => options.onExpand!(node) });
    if (options.onFocus) out.push({ key: "focus", label: "Focus here", icon: Crosshair, onSelect: () => options.onFocus!(node) });
    if (assetId) out.push({ key: "open-asset", label: "Open asset", icon: Server, onSelect: () => navigate(hrefForEntity("asset", assetId)) });
    if (identityId) out.push({ key: "open-identity", label: "Open identity", icon: Fingerprint, onSelect: () => navigate(hrefForEntity("identity", identityId)) });
    if (node.kind === "incident") out.push({ key: "open-incident", label: "Open incident", icon: Target, onSelect: () => navigate(hrefForEntity("incident", typeof node.props?.incidentId === "string" ? node.props.incidentId : node.key)) });
    if (query && session.can("event:read", orgId)) out.push({ key: "events", label: "Search events", icon: Search, hint: query, onSelect: () => navigate(searchHref(query, "7d")) });
    if (indicator && session.can("intel:read", orgId)) out.push({ key: "intel", label: "Lookup intel", icon: Target, onSelect: () => navigate(`/cti/indicators?q=${encodeURIComponent(indicator.value)}`) });
    const ai = aiContextForNode(node);
    if (ai && session.isModuleEnabled("ai_soc") && session.can("ai:use", orgId)) out.push({ key: "ai", label: "Ask AI", icon: Sparkles, onSelect: () => navigate(aiHref(ai)) });

    if (canRequest && isEndpointNode(node) && assetId) {
      out.push({
        key: "isolate",
        label: "Isolate endpoint (request)",
        icon: Lock,
        danger: true,
        hint: "High-risk: waits for approval",
        onSelect: () => setPending({ node, organizationId: orgId!, action: "isolate_endpoint", targets: { asset: [{ id: assetId, label: node.label }] } }),
      });
    }
    if (canRequest && (indicator?.type === "ip" || indicator?.type === "domain")) {
      const action: ResponseActionKey = indicator.type === "ip" ? "block_ip" : "block_domain";
      out.push({
        key: "block",
        label: indicator.type === "ip" ? "Block IP (request)" : "Block domain (request)",
        icon: Ban,
        danger: true,
        hint: "High-risk: waits for approval",
        onSelect: () => setPending({ node, organizationId: orgId!, action, targets: {}, indicator: indicator.value }),
      });
    }
    if (canRequest && identityId) {
      out.push({
        key: "disable",
        label: "Disable identity (request)",
        icon: Ban,
        danger: true,
        hint: "High-risk: waits for approval",
        onSelect: () => setPending({ node, organizationId: orgId!, action: "disable_identity", targets: { identity: [{ id: identityId, label: node.label }] } }),
      });
    }
    if (options.onHide) out.push({ key: "hide", label: "Hide from canvas", icon: EyeOff, onSelect: () => options.onHide!(node) });
    return out;
  };

  const dialog = pending ? (
    <RequestActionDialog
      open
      onClose={() => setPending(null)}
      organizationId={pending.organizationId}
      {...(options.incidentId ? { incidentId: options.incidentId } : {})}
      actions={pending.action === "isolate_endpoint" ? ["isolate_endpoint", "collect_evidence", "run_yara_scan"] : pending.action === "disable_identity" ? ["disable_identity", "revoke_sessions", "revoke_token"] : [pending.action]}
      defaultAction={pending.action}
      targets={pending.targets}
      indicatorValue={pending.indicator ?? ""}
      description={`${pending.node.label} · from the Security Graph (${nodeValue(pending.node)})`}
    />
  ) : null;

  return { actionsFor, dialog };
}
