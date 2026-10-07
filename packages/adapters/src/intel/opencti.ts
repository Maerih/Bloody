import { arr, field, int, isRecord, rec, str, type JsonRecord } from "../core/json.js";
import { EngineClient, EngineError, type EngineClientOptions } from "../http/client.js";
import { runHealthCheck, type HealthCheckResult } from "../http/health.js";
import { STIX_TLP_MARKINGS, stixIndicatorToRecords } from "./stix.js";
import type { IntelParseResult } from "./types.js";

/**
 * OpenCTI connector — reads indicators through the public GraphQL API (`POST /graphql`,
 * bearer token of a read-only OpenCTI user). Community Edition only. Indicator nodes are
 * converted to STIX-like objects and mapped by the same code as STIX bundles, so scoring and
 * relationship resolution are identical across feeds.
 *
 * Handles both label/marking shapes (OpenCTI 6 lists and OpenCTI 5 `edges`).
 */

export const OPENCTI_INDICATORS_QUERY = `
query BloodyIndicators($first: Int!, $after: ID, $filters: FilterGroup) {
  indicators(first: $first, after: $after, orderBy: modified, orderMode: asc, filters: $filters) {
    edges {
      node {
        id
        standard_id
        name
        description
        pattern
        pattern_type
        indicator_types
        x_opencti_main_observable_type
        x_opencti_score
        valid_from
        valid_until
        revoked
        confidence
        created
        modified
        createdBy { name }
        objectLabel { value }
        objectMarking { definition_type definition }
        killChainPhases { kill_chain_name phase_name }
        externalReferences { edges { node { source_name external_id url } } }
        stixCoreRelationships(relationship_type: "indicates", first: 20) {
          edges { node { to {
            ... on Malware { entity_type name }
            ... on ThreatActor { entity_type name }
            ... on IntrusionSet { entity_type name }
            ... on Campaign { entity_type name }
            ... on Tool { entity_type name }
            ... on Vulnerability { entity_type name }
            ... on AttackPattern { entity_type name x_mitre_id }
          } } }
        }
      }
    }
    pageInfo { endCursor hasNextPage globalCount }
  }
}`;

const ENTITY_TO_STIX: Record<string, string> = {
  Malware: "malware",
  "Threat-Actor": "threat-actor",
  "Threat-Actor-Group": "threat-actor",
  "Threat-Actor-Individual": "threat-actor",
  ThreatActor: "threat-actor",
  "Intrusion-Set": "intrusion-set",
  IntrusionSet: "intrusion-set",
  Campaign: "campaign",
  Tool: "tool",
  Vulnerability: "vulnerability",
  "Attack-Pattern": "attack-pattern",
  AttackPattern: "attack-pattern",
};

function listOrEdges(v: unknown): JsonRecord[] {
  if (Array.isArray(v)) return v.filter(isRecord);
  return arr(rec(v)?.["edges"])
    .map((e) => rec(rec(e)?.["node"]))
    .filter((n): n is JsonRecord => n !== undefined);
}

/** Convert an OpenCTI GraphQL indicator node into a STIX indicator + related objects. */
export function openCtiNodeToStix(node: JsonRecord): { indicator: JsonRecord; related: JsonRecord[] } {
  const id = str(node["standard_id"]) ?? `indicator--${str(node["id"]) ?? "unknown"}`;
  const markings: string[] = [];
  const related: JsonRecord[] = [];
  for (const m of listOrEdges(node["objectMarking"])) {
    const def = str(m["definition"]);
    if (str(m["definition_type"])?.toUpperCase() !== "TLP" || !def) continue;
    const known = Object.entries(STIX_TLP_MARKINGS).find(([, tlp]) => `tlp:${tlp}` === def.toLowerCase() || (tlp === "clear" && def.toUpperCase() === "TLP:WHITE"));
    if (known) markings.push(known[0]);
    else {
      const mid = `marking-definition--opencti-${def.toLowerCase().replace(/[^a-z0-9+]/g, "-")}`;
      markings.push(mid);
      related.push({ type: "marking-definition", id: mid, name: def });
    }
  }
  const relationships: JsonRecord[] = [];
  listOrEdges(node["stixCoreRelationships"]).forEach((rel, i) => {
    const to = rec(rel["to"]);
    const stixType = ENTITY_TO_STIX[str(to?.["entity_type"]) ?? ""];
    if (!to || !stixType) return;
    const targetId = `${stixType}--opencti-${id}-${i}`;
    const target: JsonRecord = { type: stixType, id: targetId, name: str(to["name"]) };
    const mitreId = str(to["x_mitre_id"]);
    if (mitreId) target["external_references"] = [{ source_name: "mitre-attack", external_id: mitreId }];
    related.push(target);
    relationships.push({ type: "relationship", relationship_type: "indicates", source_ref: id, target_ref: targetId });
  });
  related.push(...relationships);
  const indicator: JsonRecord = {
    type: "indicator",
    id,
    name: str(node["name"]),
    description: str(node["description"]),
    pattern: str(node["pattern"]),
    pattern_type: str(node["pattern_type"]) ?? "stix",
    indicator_types: arr(node["indicator_types"]),
    valid_from: str(node["valid_from"]),
    valid_until: str(node["valid_until"]),
    revoked: node["revoked"] === true,
    // OpenCTI's score is the analyst-curated value; prefer it over the generic confidence
    confidence: int(node["x_opencti_score"]) ?? int(node["confidence"]),
    created: str(node["created"]),
    modified: str(node["modified"]),
    labels: listOrEdges(node["objectLabel"])
      .map((l) => str(l["value"]))
      .filter((v): v is string => v !== undefined),
    object_marking_refs: markings,
    kill_chain_phases: arr(node["killChainPhases"]).filter(isRecord),
    external_references: listOrEdges(node["externalReferences"]),
  };
  return { indicator, related };
}

export function parseOpenCtiIndicators(response: unknown, opts: { now: string; includeRevoked?: boolean }): IntelParseResult & { endCursor: string | null; hasNextPage: boolean } {
  const conn = rec(field(response, "data.indicators"));
  const out = { records: [], skipped: [], endCursor: null, hasNextPage: false } as IntelParseResult & { endCursor: string | null; hasNextPage: boolean };
  if (!conn) {
    out.skipped.push({ ref: "response", reason: "no data.indicators in GraphQL response" });
    return out;
  }
  for (const node of listOrEdges(conn)) {
    const { indicator, related } = openCtiNodeToStix(node);
    const objects = new Map<string, JsonRecord>();
    const relations = new Map<string, JsonRecord[]>();
    objects.set(str(indicator["id"]) ?? "", indicator);
    for (const r of related) {
      if (str(r["type"]) === "relationship") relations.set(str(indicator["id"]) ?? "", [...(relations.get(str(indicator["id"]) ?? "") ?? []), r]);
      else objects.set(str(r["id"]) ?? "", r);
    }
    const res = stixIndicatorToRecords(indicator, objects, relations, { now: opts.now, source: "opencti", ...(opts.includeRevoked ? { includeRevoked: true } : {}) });
    for (const rec0 of res.records) out.records.push({ ...rec0, externalRef: rec0.externalRef.replace(/^stix:/, "opencti:") });
    out.skipped.push(...res.skipped);
  }
  out.endCursor = str(field(conn, "pageInfo.endCursor")) ?? null;
  out.hasNextPage = field(conn, "pageInfo.hasNextPage") === true;
  return out;
}

export interface OpenCtiConnectorOptions extends Omit<EngineClientOptions, "engine" | "auth"> {
  token: string;
}

export function createOpenCtiClient(opts: OpenCtiConnectorOptions): EngineClient {
  const { token, ...rest } = opts;
  return new EngineClient({ ...rest, engine: "opencti", auth: { kind: "bearer", token } });
}

function graphqlErrors(data: unknown): string | undefined {
  const errs = arr(rec(data)?.["errors"]);
  if (errs.length === 0) return undefined;
  return errs
    .map((e) => (isRecord(e) ? str(e["message"]) : undefined) ?? "error")
    .slice(0, 3)
    .join("; ");
}

/** Incremental pull: indicators modified after `since` (ISO), oldest first. */
export async function pullOpenCtiIndicators(
  client: EngineClient,
  params: { since?: string; pageSize?: number; maxPages?: number; now: string; includeRevoked?: boolean },
): Promise<IntelParseResult & { pages: number; cursor: string | null }> {
  const first = Math.min(Math.max(params.pageSize ?? 500, 1), 5000);
  const filters = params.since ? { mode: "and", filters: [{ key: "modified", values: [params.since], operator: "gt", mode: "or" }], filterGroups: [] } : null;
  const out: IntelParseResult & { pages: number; cursor: string | null } = { records: [], skipped: [], pages: 0, cursor: null };
  let after: string | null = null;
  for (let page = 1; page <= (params.maxPages ?? 100); page++) {
    const res = await client.post<unknown>("/graphql", {
      json: { query: OPENCTI_INDICATORS_QUERY, variables: { first, after, filters } },
      retry: true,
      timeoutMs: 60_000,
    });
    const err = graphqlErrors(res.data);
    if (err) throw new EngineError("invalid_response", `OpenCTI GraphQL error: ${err}`, { engine: "opencti", status: res.status, url: res.url, retryable: false });
    const parsed = parseOpenCtiIndicators(res.data, { now: params.now, ...(params.includeRevoked ? { includeRevoked: true } : {}) });
    out.records.push(...parsed.records);
    out.skipped.push(...parsed.skipped);
    out.pages = page;
    out.cursor = parsed.endCursor ?? out.cursor;
    if (!parsed.hasNextPage || !parsed.endCursor) break;
    after = parsed.endCursor;
  }
  return out;
}

export function openCtiHealthCheck(client: EngineClient): Promise<HealthCheckResult> {
  return runHealthCheck("opencti", async () => {
    const res = await client.post<unknown>("/graphql", { json: { query: "query { about { version } }" }, retry: true });
    const err = graphqlErrors(res.data);
    if (err) return { status: "unhealthy", ok: false, error: { code: "graphql_error", message: err } };
    const version = str(field(res.data, "data.about.version"));
    return { status: version ? "healthy" : "degraded", ...(version ? { version } : {}) };
  });
}
