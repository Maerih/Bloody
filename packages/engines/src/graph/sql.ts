import type { EdgeKind, GraphNode, NodeKind } from "@bloody/contracts";
import { EdgeKind as EdgeKindSchema, NodeKind as NodeKindSchema } from "@bloody/contracts";
import { GraphError, type GraphEdgeRecord, type GraphStore } from "./types.js";

/**
 * SQL-backed Security Graph store — INTERFACE ONLY.
 *
 * The control plane (`apps/api`) implements `GraphStore` on Postgres. This module fixes the
 * expected table shape, row mapping and query semantics so that implementation is
 * mechanical and behaves exactly like `InMemoryGraphStore` (the reference implementation the
 * engine tests run against).
 *
 * Expected tables (raw SQL migration owned by apps/api):
 *
 * ```sql
 * create table graph_nodes (
 *   id              uuid primary key,              -- graphNodeId(tenant, org, kind, key)  (UUIDv5, deterministic)
 *   tenant_id       uuid not null,
 *   organization_id uuid null,                     -- null = tenant-global node (technique, MSSP-wide actor …)
 *   kind            text not null,                 -- NodeKind
 *   key             text not null,                 -- natural key (see entities/keys.ts)
 *   label           text not null,
 *   props           jsonb not null default '{}'::jsonb,
 *   created_at      timestamptz not null default now(),
 *   updated_at      timestamptz not null default now()
 * );
 * create unique index graph_nodes_natural_key
 *   on graph_nodes (tenant_id, coalesce(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), kind, key);
 * create index graph_nodes_kind_key on graph_nodes (tenant_id, kind, key text_pattern_ops);   -- key / keyPrefix
 * create index graph_nodes_props on graph_nodes using gin (props jsonb_path_ops);           -- propEquals (props @> …)
 *
 * create table graph_edges (
 *   id              uuid primary key,              -- graphEdgeId(tenant, from, kind, to)  (UUIDv5, deterministic)
 *   tenant_id       uuid not null,
 *   organization_id uuid null,
 *   kind            text not null,                 -- EdgeKind
 *   from_id         uuid not null references graph_nodes(id) on delete cascade,
 *   to_id           uuid not null references graph_nodes(id) on delete cascade,
 *   props           jsonb not null default '{}'::jsonb,
 *   created_at      timestamptz not null default now(),
 *   updated_at      timestamptz not null default now(),
 *   unique (tenant_id, from_id, kind, to_id)
 * );
 * create index graph_edges_from on graph_edges (tenant_id, from_id, kind);
 * create index graph_edges_to   on graph_edges (tenant_id, to_id, kind);
 *
 * alter table graph_nodes enable row level security;   -- tenant_id = current_setting('app.tenant_id')::uuid
 * alter table graph_edges enable row level security;
 * ```
 *
 * Semantics the implementation must honour (all covered by the in-memory tests):
 *  - every statement filters `tenant_id = $tenant` (RLS is the second line of defence);
 *  - `upsertNode`: `insert … on conflict (id) do update set label = coalesce(excluded label, label),
 *    props = <mergeProps(existing, incoming, observedAt)>` — use `mergeProps` from `./props.ts`
 *    in a `select … for update` + update, or the equivalent jsonb expression;
 *  - `upsertEdge`: both endpoints must exist in the tenant; reject cross-organization edges
 *    (`resolveEdgeOrganization`); dedupe on `(from_id, kind, to_id)`;
 *  - `findNodes`: `organizationId` undefined = any org, null = `organization_id is null`;
 *    `keyPrefix` → `key like $prefix || '%'` (escape `%`/`_`); `labelContains` → `label ilike`;
 *    `propEquals` → `props @> $json`; order by kind, key, organization_id; limit ≤ 1000;
 *  - `neighbors`: may delegate to `traverseNeighbors(this, …)` or use a recursive CTE with
 *    identical results; `edgesOf` is the one-hop primitive it relies on.
 */
export interface SqlGraphStore extends GraphStore {
  readonly dialect: "postgres";
}

/** Minimal SQL executor the Postgres store is built on (pg `Pool`/`PoolClient` compatible). */
export interface SqlExecutor {
  query<R extends Record<string, unknown> = Record<string, unknown>>(sql: string, params?: readonly unknown[]): Promise<{ rows: R[]; rowCount?: number | null }>;
}

export interface GraphNodeRow extends Record<string, unknown> {
  id: string;
  tenant_id: string;
  organization_id: string | null;
  kind: string;
  key: string;
  label: string;
  props: Record<string, unknown> | string | null;
}

export interface GraphEdgeRow extends Record<string, unknown> {
  id: string;
  tenant_id: string;
  organization_id: string | null;
  kind: string;
  from_id: string;
  to_id: string;
  props: Record<string, unknown> | string | null;
}

export const GRAPH_NODES_TABLE = "graph_nodes";
export const GRAPH_EDGES_TABLE = "graph_edges";

/** Map a `graph_nodes` row to a contract node, verifying the tenant and the kind. */
export function nodeFromRow(row: GraphNodeRow, expectedTenantId: string): GraphNode {
  if (row.tenant_id !== expectedTenantId) throw new GraphError("tenant_mismatch", `Row ${row.id} belongs to another tenant`);
  const kind = NodeKindSchema.safeParse(row.kind);
  if (!kind.success) throw new GraphError("integrity", `Row ${row.id} has unknown node kind ${row.kind}`);
  return { id: row.id, kind: kind.data, key: row.key, label: row.label, organizationId: row.organization_id, props: parseProps(row.props) };
}

export function edgeFromRow(row: GraphEdgeRow, expectedTenantId: string): GraphEdgeRecord {
  if (row.tenant_id !== expectedTenantId) throw new GraphError("tenant_mismatch", `Row ${row.id} belongs to another tenant`);
  const kind = EdgeKindSchema.safeParse(row.kind);
  if (!kind.success) throw new GraphError("integrity", `Row ${row.id} has unknown edge kind ${row.kind}`);
  return { id: row.id, kind: kind.data, from: row.from_id, to: row.to_id, organizationId: row.organization_id, props: parseProps(row.props) };
}

export function nodeToRow(node: GraphNode, tenantId: string): GraphNodeRow {
  return { id: node.id, tenant_id: tenantId, organization_id: node.organizationId, kind: node.kind, key: node.key, label: node.label, props: node.props };
}

export function edgeToRow(edge: GraphEdgeRecord, tenantId: string): GraphEdgeRow {
  return { id: edge.id, tenant_id: tenantId, organization_id: edge.organizationId, kind: edge.kind, from_id: edge.from, to_id: edge.to, props: edge.props };
}

/** Escape a user-supplied prefix for `LIKE $1 || '%'`. */
export function escapeLikePattern(prefix: string): string {
  return prefix.replace(/[\\%_]/g, (c) => `\\${c}`);
}

export function isNodeKind(value: string): value is NodeKind {
  return NodeKindSchema.safeParse(value).success;
}
export function isEdgeKind(value: string): value is EdgeKind {
  return EdgeKindSchema.safeParse(value).success;
}

function parseProps(props: GraphNodeRow["props"]): Record<string, unknown> {
  if (props === null || props === undefined) return {};
  if (typeof props === "string") {
    const parsed: unknown = JSON.parse(props);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
  }
  return props;
}
