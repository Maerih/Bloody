import type { EdgeKind, NodeKind } from "@bloody/contracts";
import { stableId } from "../util/uuid.js";

/** Stable node id for `(tenant, organization, kind, key)`. Identical across store implementations. */
export function graphNodeId(tenantId: string, organizationId: string | null, kind: NodeKind, key: string): string {
  return stableId("graph-node", tenantId, organizationId, kind, key);
}

/** Stable edge id for `(tenant, from, kind, to)` — the edge dedupe key. */
export function graphEdgeId(tenantId: string, from: string, kind: EdgeKind, to: string): string {
  return stableId("graph-edge", tenantId, from, kind, to);
}
