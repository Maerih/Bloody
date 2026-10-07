import type { GraphNode, NodeKind, Subgraph } from "@bloody/contracts";
import {
  EDGES_OF_LIMIT_DEFAULT,
  FIND_LIMIT_DEFAULT,
  FIND_LIMIT_MAX,
  GraphError,
  edgeFromRow,
  escapeLikePattern,
  graphEdgeId,
  graphNodeId,
  isEdgeKind,
  mergeProps,
  nodeFromRow,
  resolveEdgeOrganization,
  traverseNeighbors,
  validateNodeInput,
  type EdgesOfOptions,
  type FindNodesQuery,
  type GraphEdgeInput,
  type GraphEdgeRecord,
  type GraphEdgeRow,
  type GraphNodeInput,
  type GraphNodeRow,
  type Neighborhood,
  type NeighborQuery,
  type SqlExecutor,
  type SqlGraphStore,
  type UpsertOptions,
} from "@bloody/engines";
import { isUuid } from "../db/pool.js";

const NODE_COLS = "id, tenant_id, organization_id, kind, key, label, props";
const EDGE_COLS = "id, tenant_id, organization_id, kind, from_id, to_id, props";

/**
 * Postgres implementation of the engines' `GraphStore`, bound to one tenant and to one
 * executor (normally the `withTenant` transaction, so RLS applies as well). Semantics mirror
 * `InMemoryGraphStore` exactly (stable UUIDv5 ids, `mergeProps` upserts, cross-organization
 * edge rejection, deterministic ordering).
 *
 * Upserts are race-safe without locks on the hot path: INSERT … ON CONFLICT DO NOTHING first;
 * only an existing row is then read FOR UPDATE, merged in TypeScript and written back.
 */
export class PostgresGraphStore implements SqlGraphStore {
  readonly dialect = "postgres" as const;

  constructor(
    private readonly sql: SqlExecutor,
    readonly tenantId: string,
  ) {
    if (!isUuid(tenantId)) throw new GraphError("invalid_input", "tenantId must be a uuid");
  }

  async upsertNode(input: GraphNodeInput, options?: UpsertOptions): Promise<GraphNode> {
    validateNodeInput(input);
    const id = graphNodeId(this.tenantId, input.organizationId, input.kind, input.key);
    const fresh = mergeProps(undefined, input.props, options);
    const inserted = await this.sql.query<GraphNodeRow>(
      `INSERT INTO graph_nodes (id, tenant_id, organization_id, kind, key, label, props)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
       ON CONFLICT (id) DO NOTHING
       RETURNING ${NODE_COLS}`,
      [id, this.tenantId, input.organizationId, input.kind, input.key, input.label ?? input.key, JSON.stringify(fresh)],
    );
    if (inserted.rows[0]) return nodeFromRow(inserted.rows[0], this.tenantId);
    const existing = await this.sql.query<GraphNodeRow>(`SELECT ${NODE_COLS} FROM graph_nodes WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, [id, this.tenantId]);
    const row = existing.rows[0];
    if (!row) throw new GraphError("integrity", `Graph node ${id} vanished during upsert`);
    const current = nodeFromRow(row, this.tenantId);
    const props = mergeProps(current.props, input.props, options);
    const label = input.label ?? current.label;
    if (label === current.label && JSON.stringify(props) === JSON.stringify(current.props)) return current;
    const updated = await this.sql.query<GraphNodeRow>(`UPDATE graph_nodes SET label = $3, props = $4::jsonb WHERE id = $1 AND tenant_id = $2 RETURNING ${NODE_COLS}`, [
      id,
      this.tenantId,
      label,
      JSON.stringify(props),
    ]);
    return nodeFromRow(updated.rows[0]!, this.tenantId);
  }

  async upsertEdge(input: GraphEdgeInput, options?: UpsertOptions): Promise<GraphEdgeRecord> {
    if (!isEdgeKind(String(input.kind))) throw new GraphError("invalid_input", `Unknown edge kind ${String(input.kind)}`);
    const ends = isUuid(input.from) && isUuid(input.to) ? await this.getNodes([input.from, input.to]) : [];
    const from = ends.find((n) => n.id === input.from);
    const to = ends.find((n) => n.id === input.to);
    if (!from || !to) throw new GraphError("integrity", `Edge ${input.kind} references a node that does not exist in tenant ${this.tenantId}`);
    const organizationId = resolveEdgeOrganization(from, to, input.organizationId);
    const id = graphEdgeId(this.tenantId, from.id, input.kind, to.id);
    const fresh = mergeProps(undefined, input.props, options);
    const inserted = await this.sql.query<GraphEdgeRow>(
      `INSERT INTO graph_edges (id, tenant_id, organization_id, kind, from_id, to_id, props)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
       ON CONFLICT (id) DO NOTHING
       RETURNING ${EDGE_COLS}`,
      [id, this.tenantId, organizationId, input.kind, from.id, to.id, JSON.stringify(fresh)],
    );
    if (inserted.rows[0]) return edgeFromRow(inserted.rows[0], this.tenantId);
    const existing = await this.sql.query<GraphEdgeRow>(`SELECT ${EDGE_COLS} FROM graph_edges WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, [id, this.tenantId]);
    const row = existing.rows[0];
    if (!row) throw new GraphError("integrity", `Graph edge ${id} vanished during upsert`);
    const current = edgeFromRow(row, this.tenantId);
    const props = mergeProps(current.props, input.props, options);
    if (JSON.stringify(props) === JSON.stringify(current.props) && current.organizationId === organizationId) return current;
    const updated = await this.sql.query<GraphEdgeRow>(`UPDATE graph_edges SET props = $3::jsonb, organization_id = $4 WHERE id = $1 AND tenant_id = $2 RETURNING ${EDGE_COLS}`, [
      id,
      this.tenantId,
      JSON.stringify(props),
      organizationId,
    ]);
    return edgeFromRow(updated.rows[0]!, this.tenantId);
  }

  async getNode(id: string): Promise<GraphNode | null> {
    if (!isUuid(id)) return null;
    const { rows } = await this.sql.query<GraphNodeRow>(`SELECT ${NODE_COLS} FROM graph_nodes WHERE id = $1 AND tenant_id = $2`, [id, this.tenantId]);
    return rows[0] ? nodeFromRow(rows[0], this.tenantId) : null;
  }

  async getNodes(ids: readonly string[]): Promise<GraphNode[]> {
    const valid = [...new Set(ids.filter(isUuid))];
    if (valid.length === 0) return [];
    const { rows } = await this.sql.query<GraphNodeRow>(`SELECT ${NODE_COLS} FROM graph_nodes WHERE tenant_id = $1 AND id = ANY($2::uuid[])`, [this.tenantId, valid]);
    const byId = new Map(rows.map((r) => [r.id, nodeFromRow(r, this.tenantId)]));
    return valid.flatMap((id) => (byId.has(id) ? [byId.get(id)!] : []));
  }

  async getNodeByKey(organizationId: string | null, kind: NodeKind, key: string): Promise<GraphNode | null> {
    return this.getNode(graphNodeId(this.tenantId, organizationId, kind, key));
  }

  async getEdge(id: string): Promise<GraphEdgeRecord | null> {
    if (!isUuid(id)) return null;
    const { rows } = await this.sql.query<GraphEdgeRow>(`SELECT ${EDGE_COLS} FROM graph_edges WHERE id = $1 AND tenant_id = $2`, [id, this.tenantId]);
    return rows[0] ? edgeFromRow(rows[0], this.tenantId) : null;
  }

  private where(query: Omit<FindNodesQuery, "limit">): { clause: string; params: unknown[] } {
    const params: unknown[] = [this.tenantId];
    const parts = ["tenant_id = $1"];
    const p = (v: unknown) => {
      params.push(v);
      return `$${params.length}`;
    };
    if (query.organizationId === null) parts.push("organization_id IS NULL");
    else if (query.organizationId !== undefined) parts.push(`organization_id = ${p(query.organizationId)}`);
    if (query.kind !== undefined) {
      if (typeof query.kind === "string") parts.push(`kind = ${p(query.kind)}`);
      else parts.push(`kind = ANY(${p([...query.kind])}::text[])`);
    }
    if (query.key !== undefined) parts.push(`key = ${p(query.key)}`);
    if (query.keyPrefix !== undefined) parts.push(`key LIKE ${p(escapeLikePattern(query.keyPrefix) + "%")}`);
    if (query.labelContains !== undefined) parts.push(`label ILIKE ${p(`%${escapeLikePattern(query.labelContains)}%`)}`);
    if (query.propEquals && Object.keys(query.propEquals).length > 0) parts.push(`props @> ${p(JSON.stringify(query.propEquals))}::jsonb`);
    return { clause: parts.join(" AND "), params };
  }

  async findNodes(query: FindNodesQuery): Promise<GraphNode[]> {
    const limit = Math.max(1, Math.min(query.limit ?? FIND_LIMIT_DEFAULT, FIND_LIMIT_MAX));
    const { clause, params } = this.where(query);
    params.push(limit);
    const { rows } = await this.sql.query<GraphNodeRow>(
      `SELECT ${NODE_COLS} FROM graph_nodes WHERE ${clause} ORDER BY kind COLLATE "C", key COLLATE "C", coalesce(organization_id::text, '') COLLATE "C" LIMIT $${params.length}`,
      params,
    );
    return rows.map((r) => nodeFromRow(r, this.tenantId));
  }

  async countNodes(query: Omit<FindNodesQuery, "limit">): Promise<number> {
    const { clause, params } = this.where(query);
    const { rows } = await this.sql.query<{ n: number | string }>(`SELECT count(*)::int AS n FROM graph_nodes WHERE ${clause}`, params);
    return Number(rows[0]?.n ?? 0);
  }

  async edgesOf(nodeIds: readonly string[], options: EdgesOfOptions): Promise<GraphEdgeRecord[]> {
    const ids = [...new Set(nodeIds.filter(isUuid))];
    if (ids.length === 0) return [];
    const limit = options.limit ?? EDGES_OF_LIMIT_DEFAULT;
    const params: unknown[] = [this.tenantId, ids];
    const dir =
      options.direction === "out" ? "from_id = ANY($2::uuid[])" : options.direction === "in" ? "to_id = ANY($2::uuid[])" : "(from_id = ANY($2::uuid[]) OR to_id = ANY($2::uuid[]))";
    let kinds = "";
    if (options.edgeKinds) {
      params.push([...options.edgeKinds]);
      kinds = ` AND kind = ANY($${params.length}::text[])`;
    }
    params.push(limit);
    const { rows } = await this.sql.query<GraphEdgeRow>(`SELECT ${EDGE_COLS} FROM graph_edges WHERE tenant_id = $1 AND ${dir}${kinds} ORDER BY id::text COLLATE "C" LIMIT $${params.length}`, params);
    return rows.map((r) => edgeFromRow(r, this.tenantId));
  }

  async neighbors(nodeId: string, options?: NeighborQuery): Promise<Neighborhood> {
    return traverseNeighbors(this, nodeId, options);
  }

  async subgraph(nodeIds: readonly string[]): Promise<Subgraph> {
    const nodes = await this.getNodes(nodeIds);
    if (nodes.length === 0) return { nodes: [], edges: [] };
    const ids = nodes.map((n) => n.id);
    const { rows } = await this.sql.query<GraphEdgeRow>(
      `SELECT ${EDGE_COLS} FROM graph_edges WHERE tenant_id = $1 AND from_id = ANY($2::uuid[]) AND to_id = ANY($2::uuid[]) ORDER BY id::text COLLATE "C"`,
      [this.tenantId, ids],
    );
    return { nodes, edges: rows.map((r) => edgeFromRow(r, this.tenantId)) };
  }

  async deleteNode(id: string): Promise<boolean> {
    if (!isUuid(id)) return false;
    const res = await this.sql.query(`DELETE FROM graph_nodes WHERE id = $1 AND tenant_id = $2`, [id, this.tenantId]);
    return (res.rowCount ?? 0) > 0;
  }

  async deleteEdge(id: string): Promise<boolean> {
    if (!isUuid(id)) return false;
    const res = await this.sql.query(`DELETE FROM graph_edges WHERE id = $1 AND tenant_id = $2`, [id, this.tenantId]);
    return (res.rowCount ?? 0) > 0;
  }
}
