import {
  CanonicalEvent as CanonicalEventSchema,
  type AssetKind,
  type CanonicalEvent,
  type Criticality,
  type EdgeKind,
  type GraphNode,
  type IndicatorType,
  type NodeKind,
  type Severity,
  type Subgraph,
} from "@bloody/contracts";
import {
  ASSET_NODE_KINDS,
  IDENTITY_NODE_KINDS,
  assetKey,
  assetLabel,
  fileKey,
  identityKey,
  indicatorKey,
  normalizeDomain,
  normalizeHostname,
  normalizeIndicatorValue,
  normalizeUrl,
  observableKindForIndicator,
  processKey,
  userKey,
  userLabel,
  type EntityRef,
} from "../entities/keys.js";
import { nullSink, type EngineEventSink } from "../notifications.js";
import { systemClock, toIso, type Clock } from "../util/clock.js";
import { isPublicIp, normalizeIp } from "../util/ip.js";
import {
  DEFAULT_ATTACK_EDGE_KINDS,
  isCrownJewel,
  isOpenVulnerabilityEdge,
  isPrivileged,
  nodeCriticality,
  rulesFor,
  vulnerabilityNodeExploitability,
  type AttackStepRule,
} from "./attack-semantics.js";
import { graphEdgeId } from "./ids.js";
import { propBool, propNumber, propString } from "./props.js";
import { GraphError, type GraphEdgeRecord, type GraphStore } from "./types.js";

/** Reference to a node: its id, or its natural key (created on demand where documented). */
export type NodeRef = string | { organizationId: string | null; kind: NodeKind; key: string };

export interface IngestResult {
  eventId: string;
  nodes: GraphNode[];
  edges: GraphEdgeRecord[];
  /** Entities of the event with their resolved graph node ids. */
  entities: Array<EntityRef & { nodeId: string }>;
}

export interface AssetGraphInput {
  id?: string;
  organizationId: string;
  kind?: AssetKind;
  name: string;
  hostname?: string | null;
  ipAddresses?: string[];
  os?: string | null;
  criticality?: Criticality;
  internetFacing?: boolean;
  tags?: string[];
  owner?: string | null;
  /** Extra posture props (edr, segmented, isolated, openPorts, exposedServices, controlStrength …). */
  props?: Record<string, unknown>;
}

export interface IdentityGraphInput {
  id?: string;
  organizationId: string;
  kind?: "user" | "service_account" | "service_principal" | "machine" | "api_key" | "group";
  provider: string;
  principal: string;
  displayName?: string | null;
  privileged?: boolean;
  mfaEnabled?: boolean;
  props?: Record<string, unknown>;
}

export interface VulnerabilityGraphInput {
  organizationId: string;
  asset: NodeRef;
  cve?: string | null;
  title: string;
  cvss?: number | null;
  epss?: number | null;
  knownExploited?: boolean;
  severity?: Severity;
  status?: "open" | "in_remediation" | "accepted" | "mitigated" | "resolved";
  patchAvailable?: boolean;
  observedAt?: string;
}

export interface IndicatorGraphInput {
  organizationId: string | null;
  type: IndicatorType;
  value: string;
  confidence?: number;
  severity?: Severity;
  source?: string;
  threatActor?: string | null;
  malware?: string | null;
  campaign?: string | null;
  tags?: string[];
  firstSeenAt?: string;
  lastSeenAt?: string;
}

export interface IncidentGraphInput {
  incidentId: string;
  organizationId: string;
  title: string;
  severity?: Severity;
  status?: string;
  detectedAt?: string;
  /** Entities involved (from detection matches / correlation); asset refs are alias-resolved. */
  entities?: EntityRef[];
  techniques?: Array<{ id: string; name?: string; tactic?: string }>;
  indicators?: Array<{ type: IndicatorType; value: string }>;
  malware?: string[];
  threatActors?: string[];
}

export interface RelatedNode {
  node: GraphNode;
  /** Human-readable relationship explanations, strongest first. */
  relations: string[];
  lastSeenAt?: string;
}

export interface Observation {
  organizationId: string | null;
  node: GraphNode;
  via: string[];
  firstSeenAt?: string;
  lastSeenAt?: string;
  count: number;
}

export interface BlastRadius {
  root: GraphNode;
  depth: number;
  total: number;
  byKind: Partial<Record<NodeKind, number>>;
  nodes: Array<{ node: GraphNode; depth: number; via: string }>;
  crownJewels: GraphNode[];
  privilegedIdentities: number;
  truncated: boolean;
}

export type SharedCategory = "infrastructure" | "identity" | "malware" | "technique" | "indicator" | "threat_actor";

export interface SharedIncident {
  incident: GraphNode;
  shared: Array<{ kind: NodeKind; key: string; label: string; category: SharedCategory }>;
  /** Weighted overlap score — indicators/malware/actors weigh more than shared techniques. */
  score: number;
}

export interface OrganizationImpact {
  organizationId: string;
  observations: number;
  assets: number;
  identities: number;
  firstSeenAt?: string;
  lastSeenAt?: string;
}

export interface SecurityGraphOptions {
  store: GraphStore;
  clock?: Clock;
  sink?: EngineEventSink;
  /** zod-validate events on ingest (default true). */
  validateEvents?: boolean;
  /** Bound of the alias-resolution cache (default 10 000 entries, 0 disables). */
  resolutionCacheSize?: number;
}

const ACCESS_EDGES: readonly EdgeKind[] = ["admin_of", "owns", "has_access_to", "logged_into"];
const ACCESS_STRENGTH: Record<string, number> = { admin_of: 0, owns: 1, has_access_to: 2, logged_into: 3, process: 4 };
const WRITE_ACTIONS = new Set(["create", "modify", "rename", "delete"]);
const MAX_COMMAND_LINE = 2000;

/**
 * The Security Graph service: entity resolution + ingestion on top of a tenant-bound
 * {@link GraphStore}, and the relationship queries the platform needs (assets of an identity,
 * where an IOC was observed, who can reach an asset, blast radius, incidents sharing
 * infrastructure/identity/malware/technique/indicators, organizations affected by an IOC).
 *
 * Edge ontology produced by ingestion (`from -[kind]-> to`):
 *   user -authenticates_as-> identity            (OS / directory account ↔ IdP principal)
 *   identity|user -logged_into-> endpoint         (successful logon; process owner)
 *   ip -authenticates_as-> identity|user          (successful logon from that source address)
 *   ip -connected_to-> endpoint                   (failed logon / inbound connection)
 *   process -runs_on-> endpoint, process -spawned-> process, process -authenticates_as-> user
 *   process -executed-> file (image), process -wrote|has_access_to|executed-> file
 *   endpoint -contains-> file, file -has_hash-> hash
 *   process|endpoint -connected_to-> ip|domain|url, domain -resolves_to-> ip, domain -contains-> url
 *   indicator -indicates-> observable (ip/domain/url/hash), indicator -observed_on-> endpoint|identity|user
 *   indicator -attributed_to-> threat_actor|malware|campaign
 *   technique -observed_on-> endpoint|identity   (technique nodes are tenant-global)
 *   internet -exposes-> asset, asset -has_vulnerability-> vulnerability
 *   identity -has_access_to-> cloud_asset          (cloud audit activity)
 *   incident -involves-> any entity
 */
export class SecurityGraph {
  readonly store: GraphStore;
  private readonly clock: Clock;
  private readonly sink: EngineEventSink;
  private readonly validateEvents: boolean;
  private readonly cacheSize: number;
  private readonly aliasCache = new Map<string, string>();

  constructor(options: SecurityGraphOptions) {
    this.store = options.store;
    this.clock = options.clock ?? systemClock;
    this.sink = options.sink ?? nullSink;
    this.validateEvents = options.validateEvents ?? true;
    this.cacheSize = options.resolutionCacheSize ?? 10_000;
  }

  get tenantId(): string {
    return this.store.tenantId;
  }

  // ─── Ingestion ────────────────────────────────────────────────────────────

  async ingestEvent(input: CanonicalEvent): Promise<IngestResult> {
    const event = this.validateEvents ? CanonicalEventSchema.parse(input) : input;
    if (event.tenantId !== this.tenantId) throw new GraphError("tenant_mismatch", `Event ${event.id} belongs to tenant ${event.tenantId}, graph is bound to ${this.tenantId}`);
    const org = event.organizationId;
    const at = event.timestamp;
    const nodes = new Map<string, GraphNode>();
    const edges = new Map<string, GraphEdgeRecord>();
    const entities = new Map<string, EntityRef & { nodeId: string }>();

    const node = async (kind: NodeKind, key: string, label: string, props: Record<string, unknown> = {}, role?: EntityRef["role"], organizationId: string | null = org) => {
      const n = await this.store.upsertNode({ organizationId, kind, key, label, props }, { observedAt: at });
      nodes.set(n.id, n);
      const entityId = `${kind}:${key}`;
      if (!entities.has(entityId)) entities.set(entityId, { kind, key, label: n.label, nodeId: n.id, ...(role ? { role } : {}) });
      return n;
    };
    const edge = async (from: GraphNode, kind: EdgeKind, to: GraphNode, props: Record<string, unknown> = {}) => {
      if (from.id === to.id) return null;
      const e = await this.store.upsertEdge({ kind, from: from.id, to: to.id, organizationId: org, props }, { observedAt: at });
      edges.set(e.id, e);
      return e;
    };

    // Asset (alias-resolved)
    const endpoint = event.asset ? await this.resolveEventAsset(event) : null;
    if (endpoint) {
      nodes.set(endpoint.id, endpoint);
      entities.set(`${endpoint.kind}:${endpoint.key}`, { kind: endpoint.kind, key: endpoint.key, label: endpoint.label, nodeId: endpoint.id, role: "target" });
    }
    const endpointKey = endpoint?.key ?? null;

    // Principals
    const uk = userKey(event.user);
    const user = uk && event.user ? await node("user", uk, userLabel(event.user, uk), { name: event.user.name, domain: event.user.domain, sid: event.user.sid, email: event.user.email }, "actor") : null;
    const ik = identityKey(event);
    const identity =
      ik && event.identity
        ? await node(
            "identity",
            ik,
            event.identity.principal ?? ik,
            { provider: event.identity.provider ?? event.source.product, principal: event.identity.principal, privileged: event.identity.privileged, mfa: event.identity.mfa },
            "actor",
          )
        : null;
    if (user && identity) await edge(user, "authenticates_as", identity);

    // Authentication semantics
    const outcome = event.outcome ?? event.identity?.outcome;
    const isAuth = event.category === "authentication" || (event.category === "identity" && outcome !== undefined);
    const authSource = event.identity?.sourceIp ?? event.network?.srcIp;
    const authSourceIp = authSource ? normalizeIp(authSource) : null;
    if (isAuth) {
      const actors = [identity, user].filter((a): a is GraphNode => a !== null);
      const ipNode = authSourceIp ? await node("ip", authSourceIp, authSourceIp, { public: isPublicIp(authSourceIp) }, "source") : null;
      if (outcome === "success") {
        for (const a of actors) {
          if (endpoint) await edge(a, "logged_into", endpoint, { via: "authentication" });
          if (ipNode) await edge(ipNode, "authenticates_as", a, { country: event.identity?.geo?.country, city: event.identity?.geo?.city });
        }
      } else if (outcome === "failure" && ipNode && endpoint) {
        await edge(ipNode, "connected_to", endpoint, { authFailure: true });
      }
    }

    // Process tree
    let proc: GraphNode | null = null;
    if (event.process && endpoint && endpointKey) {
      const p = event.process;
      const pk = processKey(endpointKey, p);
      if (pk) {
        proc = await node("process", pk, p.name ?? p.path ?? pk, { pid: p.pid, name: p.name, path: p.path, commandLine: truncate(p.commandLine), user: p.user, hashSha256: p.hashSha256?.toLowerCase() }, "actor");
        await edge(proc, "runs_on", endpoint);
        if (p.parent && (p.parent.pid !== undefined || p.parent.path || p.parent.name)) {
          const ppk = processKey(endpointKey, p.parent);
          if (ppk) {
            const parent = await node("process", ppk, p.parent.name ?? p.parent.path ?? ppk, { pid: p.parent.pid, name: p.parent.name, path: p.parent.path, commandLine: truncate(p.parent.commandLine) });
            await edge(parent, "spawned", proc);
            await edge(parent, "runs_on", endpoint);
          }
        }
        let image: GraphNode | null = null;
        if (p.path) {
          image = await node("file", fileKey(endpointKey, p.path), p.path, { path: p.path, name: p.name, image: true }, "artifact");
          await edge(proc, "executed", image);
          await edge(endpoint, "contains", image);
        }
        if (p.hashSha256 && /^[0-9a-f]{64}$/i.test(p.hashSha256)) {
          const h = await node("hash", p.hashSha256.toLowerCase(), p.hashSha256.toLowerCase(), { algorithm: "sha256" }, "artifact");
          await edge(image ?? proc, "has_hash", h);
        }
        if (p.user) {
          const puk = userKey({ name: p.user });
          if (puk) {
            const pu = await node("user", puk, p.user, { name: p.user }, "actor");
            await edge(proc, "authenticates_as", pu);
            await edge(pu, "logged_into", endpoint, { via: "process" });
          }
        }
      }
    }

    // File activity
    if (event.file?.path) {
      const f = event.file;
      const fileNode = await node("file", fileKey(endpointKey, f.path!), f.path!, { path: f.path, name: f.name, size: f.size, lastAction: f.action }, "artifact");
      if (endpoint) await edge(endpoint, "contains", fileNode);
      if (proc && f.action) {
        const kind: EdgeKind = WRITE_ACTIONS.has(f.action) ? "wrote" : f.action === "execute" ? "executed" : "has_access_to";
        await edge(proc, kind, fileNode, { action: f.action });
      }
      for (const [algorithm, value] of [
        ["sha256", f.sha256],
        ["md5", f.md5],
      ] as const) {
        if (value && /^[0-9a-f]+$/i.test(value)) {
          const h = await node("hash", value.toLowerCase(), value.toLowerCase(), { algorithm }, "artifact");
          await edge(fileNode, "has_hash", h);
        }
      }
    }

    // Network activity
    const net = event.network;
    if (net) {
      const actor = proc ?? endpoint;
      const assetIps = new Set((event.asset?.ip ?? []).map((i) => normalizeIp(i)).filter((i): i is string => i !== null));
      const src = net.srcIp ? normalizeIp(net.srcIp) : null;
      const dst = net.dstIp ? normalizeIp(net.dstIp) : null;
      let direction = net.direction ?? "unknown";
      if (direction === "unknown") direction = src && assetIps.has(src) ? "outbound" : dst && assetIps.has(dst) ? "inbound" : "outbound";
      let dstNode: GraphNode | null = null;
      if (direction === "inbound") {
        if (src && endpoint && !(isAuth && src === authSourceIp)) {
          const srcNode = await node("ip", src, src, { public: isPublicIp(src) }, "source");
          await edge(srcNode, "connected_to", endpoint, { protocol: net.protocol, dstPort: net.dstPort });
        }
      } else if (dst && !assetIps.has(dst)) {
        dstNode = await node("ip", dst, dst, { public: isPublicIp(dst) }, "destination");
        if (actor) await edge(actor, "connected_to", dstNode, { protocol: net.protocol, dstPort: net.dstPort, direction });
      }
      const domainSources: Array<[string | undefined, string]> = [
        [net.dnsQuery, "dns"],
        [net.httpHost, "http"],
        [net.tlsSni, "tls"],
      ];
      for (const [raw, via] of domainSources) {
        const d = raw ? normalizeDomain(raw) : null;
        if (!d) continue;
        const dn = await node("domain", d, d, {}, "destination");
        if (actor && direction !== "inbound") await edge(actor, "connected_to", dn, { via });
        if (dstNode && via !== "dns") await edge(dn, "resolves_to", dstNode);
      }
      if (net.httpUrl) {
        const u = normalizeUrl(net.httpUrl);
        if (u) {
          const un = await node("url", u, u, {}, "destination");
          if (actor && direction !== "inbound") await edge(actor, "connected_to", un, { via: "http" });
          const host = safeHost(u);
          if (host) {
            const hn = await node("domain", host, host, {});
            await edge(hn, "contains", un);
          }
        }
      }
    }

    // Cloud resources acted upon
    if (event.cloudResource?.resourceId) {
      const c = event.cloudResource;
      const key = [c.provider, c.accountId ?? "-", c.resourceId].join(":").toLowerCase();
      const cr = await node("cloud_asset", key, c.resourceId!, { provider: c.provider, accountId: c.accountId, region: c.region, resourceType: c.resourceType }, "target");
      const actor = identity ?? user;
      if (actor) await edge(actor, "has_access_to", cr, { action: c.action, via: "cloud_audit" });
    }

    // Indicators (CTI enrichment results carried on the event)
    const observedTargets = [endpoint, identity ?? user].filter((n): n is GraphNode => n !== null);
    for (const ind of event.indicators ?? []) {
      const key = indicatorKey(ind.type, ind.value);
      if (!key) continue;
      const value = key.slice(ind.type.length + 1);
      const indNode = await node("indicator", key, ind.value, { type: ind.type, value }, "observable");
      const obsKind = observableKindForIndicator(ind.type);
      if (obsKind && !value.includes("/")) {
        const obs = await node(obsKind, value, value, obsKind === "ip" ? { public: isPublicIp(value) } : {});
        await edge(indNode, "indicates", obs);
      }
      for (const t of observedTargets) await edge(indNode, "observed_on", t, { eventId: event.id, eventType: event.eventType });
    }

    // ATT&CK techniques (tenant-global knowledge nodes)
    for (const t of event.attack ?? []) {
      const tech = await node("technique", t.id.toUpperCase(), t.name ? `${t.id} ${t.name}` : t.id, { name: t.name, tactic: t.tactic }, "observable", null);
      for (const target of observedTargets) await edge(tech, "observed_on", target, { eventId: event.id });
    }

    return { eventId: event.id, nodes: [...nodes.values()], edges: [...edges.values()], entities: [...entities.values()] };
  }

  /** Upsert an inventory asset with its posture props and internet exposure edge. */
  async ingestAsset(asset: AssetGraphInput): Promise<GraphNode> {
    const org = asset.organizationId;
    const existing = await this.findAsset(org, {
      ...(asset.id ? { id: asset.id } : {}),
      ...(asset.hostname ? { hostname: asset.hostname } : {}),
    });
    const kind = existing?.kind ?? assetNodeKind(asset.kind ?? "endpoint");
    const key = existing?.key ?? (asset.hostname ? normalizeHostname(asset.hostname) : null) ?? (asset.id ? `asset:${asset.id.toLowerCase()}` : `name:${asset.name.trim().toLowerCase()}`);
    const n = await this.store.upsertNode({
      organizationId: org,
      kind,
      key,
      label: asset.name,
      props: {
        ...asset.props,
        assetId: asset.id,
        assetKind: asset.kind,
        hostname: asset.hostname ?? undefined,
        hostKey: asset.hostname ? (normalizeHostname(asset.hostname) ?? undefined) : undefined,
        ips: asset.ipAddresses,
        os: asset.os ?? undefined,
        criticality: asset.criticality,
        internetFacing: asset.internetFacing,
        tags: asset.tags,
        owner: asset.owner ?? undefined,
      },
    });
    this.remember(org, n, { id: asset.id, hostname: asset.hostname ?? undefined });
    if (asset.internetFacing !== undefined) {
      const internet = await this.ensureInternet(org);
      if (asset.internetFacing) {
        await this.store.upsertEdge({ kind: "exposes", from: internet.id, to: n.id, organizationId: org, props: { source: "inventory" } });
      } else {
        await this.store.deleteEdge(graphEdgeId(this.tenantId, internet.id, "exposes", n.id));
      }
    }
    return n;
  }

  /** Upsert an IdP / directory identity (privilege + MFA posture feed attack paths and risk). */
  async ingestIdentity(input: IdentityGraphInput): Promise<GraphNode> {
    const kind: NodeKind = input.kind === "group" ? "group" : input.kind === "api_key" ? "credential" : "identity";
    const key = `${input.provider.trim().toLowerCase()}:${input.principal.trim().toLowerCase()}`;
    return this.store.upsertNode({
      organizationId: input.organizationId,
      kind,
      key,
      label: input.displayName ?? input.principal,
      props: { ...input.props, identityId: input.id, identityKind: input.kind, provider: input.provider, principal: input.principal, privileged: input.privileged, mfa: input.mfaEnabled },
    });
  }

  /**
   * Link a vulnerability finding to an asset. Vulnerability nodes are per organization and keyed
   * by CVE (CVE-level props: cvss/epss/KEV); per-asset state (status, patch) lives on the edge.
   * Emits `vulnerability.kev_detected` the first time an open KEV finding lands on an asset.
   */
  async ingestVulnerability(input: VulnerabilityGraphInput): Promise<{ vulnerability: GraphNode; edge: GraphEdgeRecord }> {
    const asset = await this.resolveRef(input.asset);
    if (asset.organizationId !== input.organizationId) throw new GraphError("integrity", "Vulnerability organization does not match the asset organization");
    const key = input.cve ? input.cve.trim().toUpperCase() : `vuln:${input.title.trim().toLowerCase()}`;
    const vuln = await this.store.upsertNode({
      organizationId: input.organizationId,
      kind: "vulnerability",
      key,
      label: input.cve ? `${input.cve.toUpperCase()} ${input.title}`.trim() : input.title,
      props: { cve: input.cve ?? undefined, title: input.title, cvss: input.cvss ?? undefined, epss: input.epss ?? undefined, knownExploited: input.knownExploited, severity: input.severity },
    });
    const edgeId = graphEdgeId(this.tenantId, asset.id, "has_vulnerability", vuln.id);
    const before = await this.store.getEdge(edgeId);
    const e = await this.store.upsertEdge(
      { kind: "has_vulnerability", from: asset.id, to: vuln.id, organizationId: input.organizationId, props: { status: input.status ?? "open", patchAvailable: input.patchAvailable, severity: input.severity } },
      input.observedAt ? { observedAt: input.observedAt } : undefined,
    );
    const wasOpenKev = before !== null && isOpenVulnerabilityEdge(before.props) && propBool(vuln.props, "knownExploited") === true;
    if (input.knownExploited && isOpenVulnerabilityEdge(e.props) && !wasOpenKev) {
      this.sink.emit({
        type: "vulnerability.kev_detected",
        tenantId: this.tenantId,
        organizationId: input.organizationId,
        at: toIso(this.clock.now()),
        cve: key,
        assetNodeId: asset.id,
        assetLabel: asset.label,
        internetFacing: propBool(asset.props, "internetFacing") === true,
        criticality: nodeCriticality(asset),
      });
    }
    return { vulnerability: vuln, edge: e };
  }

  /** Upsert a threat-intelligence indicator with its observable and attribution. */
  async ingestIndicator(input: IndicatorGraphInput): Promise<GraphNode> {
    const key = indicatorKey(input.type, input.value);
    if (!key) throw new GraphError("invalid_input", `Invalid ${input.type} indicator value`);
    const value = key.slice(input.type.length + 1);
    const ind = await this.store.upsertNode({
      organizationId: input.organizationId,
      kind: "indicator",
      key,
      label: input.value,
      props: {
        type: input.type,
        value,
        confidence: input.confidence,
        severity: input.severity,
        source: input.source,
        threatActor: input.threatActor ?? undefined,
        malware: input.malware ?? undefined,
        campaign: input.campaign ?? undefined,
        tags: input.tags,
        intelFirstSeenAt: input.firstSeenAt,
        intelLastSeenAt: input.lastSeenAt,
      },
    });
    const obsKind = observableKindForIndicator(input.type);
    if (obsKind && !value.includes("/")) {
      const obs = await this.store.upsertNode({ organizationId: input.organizationId, kind: obsKind, key: value, label: value, props: obsKind === "ip" ? { public: isPublicIp(value) } : {} });
      await this.store.upsertEdge({ kind: "indicates", from: ind.id, to: obs.id, organizationId: input.organizationId });
    }
    const attribution: Array<[NodeKind, string | null | undefined]> = [
      ["threat_actor", input.threatActor],
      ["malware", input.malware],
      ["campaign", input.campaign],
    ];
    for (const [kind, name] of attribution) {
      if (!name) continue;
      const target = await this.store.upsertNode({ organizationId: input.organizationId, kind, key: name.trim().toLowerCase(), label: name.trim() });
      await this.store.upsertEdge({ kind: "attributed_to", from: ind.id, to: target.id, organizationId: input.organizationId });
    }
    return ind;
  }

  /** Create/refresh an incident node and its `involves` edges (enables incidentsSharing). */
  async linkIncident(input: IncidentGraphInput): Promise<GraphNode> {
    const org = input.organizationId;
    const inc = await this.store.upsertNode({
      organizationId: org,
      kind: "incident",
      key: input.incidentId.toLowerCase(),
      label: input.title,
      props: { incidentId: input.incidentId, severity: input.severity, status: input.status, detectedAt: input.detectedAt },
    });
    const involve = async (target: GraphNode) => {
      if (target.id !== inc.id) await this.store.upsertEdge({ kind: "involves", from: inc.id, to: target.id, organizationId: org });
    };
    for (const ref of input.entities ?? []) {
      if (ref.kind === "incident") continue;
      let target: GraphNode | null = null;
      if (ASSET_NODE_KINDS.includes(ref.kind)) target = await this.findAssetByKey(org, ref.key);
      if (!target) {
        const global = ref.kind === "technique";
        target = await this.store.upsertNode({ organizationId: global ? null : org, kind: ref.kind, key: ref.key, label: ref.label });
      }
      await involve(target);
    }
    for (const t of input.techniques ?? []) {
      await involve(await this.store.upsertNode({ organizationId: null, kind: "technique", key: t.id.toUpperCase(), label: t.name ? `${t.id} ${t.name}` : t.id, props: { name: t.name, tactic: t.tactic } }));
    }
    for (const i of input.indicators ?? []) {
      const key = indicatorKey(i.type, i.value);
      if (key) await involve(await this.store.upsertNode({ organizationId: org, kind: "indicator", key, label: i.value, props: { type: i.type, value: key.slice(i.type.length + 1) } }));
    }
    for (const m of input.malware ?? []) await involve(await this.store.upsertNode({ organizationId: org, kind: "malware", key: m.trim().toLowerCase(), label: m.trim() }));
    for (const a of input.threatActors ?? []) await involve(await this.store.upsertNode({ organizationId: org, kind: "threat_actor", key: a.trim().toLowerCase(), label: a.trim() }));
    return inc;
  }

  /**
   * Generic relationship upsert for adapters/posture feeds (CIEM admin rights, network
   * reachability scans, credential stores, domain trusts …). Natural-key refs are created on demand.
   */
  async relate(from: NodeRef, kind: EdgeKind, to: NodeRef, props: Record<string, unknown> = {}, observedAt?: string): Promise<GraphEdgeRecord> {
    const [a, b] = [await this.resolveRef(from, true), await this.resolveRef(to, true)];
    return this.store.upsertEdge({ kind, from: a.id, to: b.id, props }, observedAt ? { observedAt } : undefined);
  }

  /** The per-organization "internet" entry node for exposure and attack paths. */
  async ensureInternet(organizationId: string): Promise<GraphNode> {
    return this.store.upsertNode({ organizationId, kind: "internet", key: "internet", label: "Internet", props: { entry: true } });
  }

  // ─── Relationship queries ─────────────────────────────────────────────────

  /** "What assets are associated with this identity?" */
  async assetsForIdentity(ref: NodeRef): Promise<RelatedNode[]> {
    const start = await this.resolveRef(ref);
    const principals = new Map<string, { node: GraphNode; via: string }>([[start.id, { node: start, via: "" }]]);
    // linked accounts: user ↔ identity over authenticates_as (both directions)
    for (const e of await this.store.edgesOf([start.id], { direction: "both", edgeKinds: ["authenticates_as"] })) {
      const otherId = e.from === start.id ? e.to : e.from;
      const [other] = await this.store.getNodes([otherId]);
      if (other && IDENTITY_NODE_KINDS.includes(other.kind)) principals.set(other.id, { node: other, via: ` via linked account ${other.label}` });
    }
    // group memberships, transitively (max 3 levels)
    let frontier = [...principals.keys()];
    for (let level = 0; level < 3 && frontier.length > 0; level++) {
      const groupEdges = await this.store.edgesOf(frontier, { direction: "out", edgeKinds: ["member_of"] });
      const groups = await this.store.getNodes(groupEdges.map((e) => e.to).filter((id) => !principals.has(id)));
      frontier = [];
      for (const g of groups) {
        principals.set(g.id, { node: g, via: ` via group ${g.label}` });
        frontier.push(g.id);
      }
    }
    const results = new Map<string, { node: GraphNode; relations: Array<[number, string]>; lastSeenAt?: string }>();
    const record = (n: GraphNode, strength: number, text: string, lastSeenAt?: string) => {
      const r = results.get(n.id) ?? { node: n, relations: [] };
      if (!r.relations.some(([, t]) => t === text)) r.relations.push([strength, text]);
      if (lastSeenAt && (!r.lastSeenAt || lastSeenAt > r.lastSeenAt)) r.lastSeenAt = lastSeenAt;
      results.set(n.id, r);
    };
    const accessEdges = await this.store.edgesOf([...principals.keys()], { direction: "out", edgeKinds: ACCESS_EDGES });
    const targets = new Map((await this.store.getNodes(accessEdges.map((e) => e.to))).map((n) => [n.id, n]));
    for (const e of accessEdges) {
      const t = targets.get(e.to);
      if (!t || !ASSET_NODE_KINDS.includes(t.kind)) continue;
      record(t, ACCESS_STRENGTH[e.kind] ?? 9, `${e.kind}${principals.get(e.from)?.via ?? ""}`, propString(e.props, "lastSeenAt"));
    }
    // processes running as the principal
    const procEdges = await this.store.edgesOf([...principals.keys()], { direction: "in", edgeKinds: ["authenticates_as"] });
    const procIds = procEdges.map((e) => e.from);
    const procs = (await this.store.getNodes(procIds)).filter((p) => p.kind === "process");
    if (procs.length > 0) {
      const runsOn = await this.store.edgesOf(procs.map((p) => p.id), { direction: "out", edgeKinds: ["runs_on"] });
      const hosts = new Map((await this.store.getNodes(runsOn.map((e) => e.to))).map((n) => [n.id, n]));
      for (const e of runsOn) {
        const h = hosts.get(e.to);
        if (h) record(h, ACCESS_STRENGTH.process!, "ran processes on", propString(e.props, "lastSeenAt"));
      }
    }
    return [...results.values()]
      .map((r) => ({ node: r.node, relations: r.relations.sort((a, b) => a[0] - b[0]).map(([, t]) => t), ...(r.lastSeenAt ? { lastSeenAt: r.lastSeenAt } : {}) }))
      .sort((a, b) => strengthOf(a.relations) - strengthOf(b.relations) || a.node.label.localeCompare(b.node.label));
  }

  /** "What identities can reach this asset?" (direct rights, via groups, linked accounts, process owners). */
  async identitiesReaching(ref: NodeRef, options: { groupDepth?: number } = {}): Promise<Array<RelatedNode & { privileged: boolean }>> {
    const asset = await this.resolveRef(ref);
    const results = new Map<string, { node: GraphNode; relations: Array<[number, string]>; lastSeenAt?: string }>();
    const record = (n: GraphNode, strength: number, text: string, lastSeenAt?: string) => {
      if (!IDENTITY_NODE_KINDS.includes(n.kind)) return;
      const r = results.get(n.id) ?? { node: n, relations: [] };
      if (!r.relations.some(([, t]) => t === text)) r.relations.push([strength, text]);
      if (lastSeenAt && (!r.lastSeenAt || lastSeenAt > r.lastSeenAt)) r.lastSeenAt = lastSeenAt;
      results.set(n.id, r);
    };
    const direct = await this.store.edgesOf([asset.id], { direction: "in", edgeKinds: ACCESS_EDGES });
    const directNodes = new Map((await this.store.getNodes(direct.map((e) => e.from))).map((n) => [n.id, n]));
    let groupFrontier: Array<{ id: string; label: string; relation: string }> = [];
    for (const e of direct) {
      const n = directNodes.get(e.from);
      if (!n) continue;
      record(n, ACCESS_STRENGTH[e.kind] ?? 9, e.kind, propString(e.props, "lastSeenAt"));
      if (n.kind === "group") groupFrontier.push({ id: n.id, label: n.label, relation: e.kind });
    }
    // expand group members (nested groups, cycle-safe)
    const expandedGroups = new Set(groupFrontier.map((g) => g.id));
    for (let level = 0; level < (options.groupDepth ?? 3) && groupFrontier.length > 0; level++) {
      const memberEdges = await this.store.edgesOf(groupFrontier.map((g) => g.id), { direction: "in", edgeKinds: ["member_of"] });
      const members = new Map((await this.store.getNodes(memberEdges.map((e) => e.from))).map((n) => [n.id, n]));
      const byGroup = new Map(groupFrontier.map((g) => [g.id, g]));
      const next: typeof groupFrontier = [];
      for (const e of memberEdges) {
        const m = members.get(e.from);
        const g = byGroup.get(e.to);
        if (!m || !g) continue;
        record(m, (ACCESS_STRENGTH[g.relation] ?? 9) + 0.5, `${g.relation} via group ${g.label}`);
        if (m.kind === "group" && !expandedGroups.has(m.id)) {
          expandedGroups.add(m.id);
          next.push({ id: m.id, label: m.label, relation: g.relation });
        }
      }
      groupFrontier = next;
    }
    // process owners on the asset
    const procEdges = await this.store.edgesOf([asset.id], { direction: "in", edgeKinds: ["runs_on"] });
    if (procEdges.length > 0) {
      const ownerEdges = await this.store.edgesOf(procEdges.map((e) => e.from), { direction: "out", edgeKinds: ["authenticates_as"] });
      for (const n of await this.store.getNodes(ownerEdges.map((e) => e.to))) record(n, ACCESS_STRENGTH.process!, "ran processes on asset");
    }
    // linked accounts of everything found so far
    const found = [...results.values()].filter((r) => r.node.kind === "user" || r.node.kind === "identity");
    if (found.length > 0) {
      const links = await this.store.edgesOf(found.map((r) => r.node.id), { direction: "both", edgeKinds: ["authenticates_as"] });
      const linkedNodes = new Map((await this.store.getNodes(links.flatMap((e) => [e.from, e.to]))).map((n) => [n.id, n]));
      for (const e of links) {
        const knownSide = results.has(e.from) ? e.from : e.to;
        const otherSide = knownSide === e.from ? e.to : e.from;
        const other = linkedNodes.get(otherSide);
        const known = results.get(knownSide);
        if (other && known && !results.has(other.id)) record(other, strengthOf(known.relations.map(([, t]) => t)) + 0.25, `linked account of ${known.node.label}`);
      }
    }
    return [...results.values()]
      .map((r) => ({ node: r.node, relations: r.relations.sort((a, b) => a[0] - b[0]).map(([, t]) => t), privileged: isPrivileged(r.node), ...(r.lastSeenAt ? { lastSeenAt: r.lastSeenAt } : {}) }))
      .sort((a, b) => Number(b.privileged) - Number(a.privileged) || strengthOf(a.relations) - strengthOf(b.relations) || a.node.label.localeCompare(b.node.label));
  }

  /** "Where was this IOC observed?" — across the organization, or the whole tenant when omitted. */
  async whereObserved(indicator: { type: IndicatorType; value: string } | string, options: { organizationId?: string } = {}): Promise<Observation[]> {
    let type: IndicatorType;
    let value: string;
    if (typeof indicator === "string") {
      const n = await this.store.getNode(indicator);
      if (!n || n.kind !== "indicator") throw new GraphError("not_found", `Indicator node ${indicator} not found`);
      type = (propString(n.props, "type") as IndicatorType | undefined) ?? (n.key.split(":")[0] as IndicatorType);
      value = propString(n.props, "value") ?? n.key.slice(type.length + 1);
    } else {
      type = indicator.type;
      const v = normalizeIndicatorValue(indicator.type, indicator.value);
      if (v === null) throw new GraphError("invalid_input", `Invalid ${indicator.type} indicator value`);
      value = v;
    }
    const org = options.organizationId;
    const out = new Map<string, Observation>();
    const add = (n: GraphNode, via: string, props: Record<string, unknown>) => {
      const o = out.get(n.id) ?? { organizationId: n.organizationId, node: n, via: [], count: 0 };
      if (!o.via.includes(via)) o.via.push(via);
      o.count += propNumber(props, "seenCount") ?? 1;
      const f = propString(props, "firstSeenAt");
      const l = propString(props, "lastSeenAt");
      if (f && (!o.firstSeenAt || f < o.firstSeenAt)) o.firstSeenAt = f;
      if (l && (!o.lastSeenAt || l > o.lastSeenAt)) o.lastSeenAt = l;
      out.set(n.id, o);
    };

    // 1) indicator nodes matched in telemetry
    const indNodes = await this.store.findNodes({ kind: "indicator", key: `${type}:${value}`, ...(org !== undefined ? { organizationId: org } : {}), limit: 1000 });
    if (indNodes.length > 0) {
      const obsEdges = await this.store.edgesOf(indNodes.map((n) => n.id), { direction: "out", edgeKinds: ["observed_on"] });
      const targets = new Map((await this.store.getNodes(obsEdges.map((e) => e.to))).map((n) => [n.id, n]));
      for (const e of obsEdges) {
        const t = targets.get(e.to);
        if (t) add(t, "indicator match", e.props);
      }
    }
    // 2) the raw observable in telemetry (connections, file hashes)
    const obsKind = observableKindForIndicator(type);
    if (obsKind && !value.includes("/")) {
      const observables = await this.store.findNodes({ kind: obsKind, key: value, ...(org !== undefined ? { organizationId: org } : {}), limit: 1000 });
      if (observables.length > 0) {
        const ids = observables.map((n) => n.id);
        const inbound = await this.store.edgesOf(ids, { direction: "in", edgeKinds: ["connected_to", "has_hash", "authenticates_as"] });
        const outbound = await this.store.edgesOf(ids, { direction: "out", edgeKinds: ["connected_to", "authenticates_as"] });
        const related = new Map((await this.store.getNodes([...inbound.map((e) => e.from), ...outbound.map((e) => e.to)])).map((n) => [n.id, n]));
        for (const e of inbound) {
          const src = related.get(e.from);
          if (!src) continue;
          if (src.kind === "process") {
            for (const host of await this.hostsOfProcess(src.id)) add(host, `process ${src.label} connected to ${value}`, e.props);
          } else if (src.kind === "file") {
            for (const host of await this.hostsOfFile(src.id)) add(host, `file ${src.label} has hash ${value}`, e.props);
          } else if (src.kind !== "indicator" && src.kind !== "domain") {
            add(src, e.kind === "has_hash" ? "artifact hash" : `connected to ${value}`, e.props);
          }
        }
        for (const e of outbound) {
          const dst = related.get(e.to);
          if (dst && (ASSET_NODE_KINDS.includes(dst.kind) || IDENTITY_NODE_KINDS.includes(dst.kind))) add(dst, e.kind === "authenticates_as" ? `logon from ${value}` : `inbound connection from ${value}`, e.props);
        }
      }
    }
    return [...out.values()].sort((a, b) => (b.lastSeenAt ?? "").localeCompare(a.lastSeenAt ?? "") || a.node.label.localeCompare(b.node.label));
  }

  /** "Which organizations are affected by this IOC?" (tenant-wide; MSSP portfolio view). */
  async orgsAffectedByIndicator(type: IndicatorType, value: string): Promise<OrganizationImpact[]> {
    const observations = await this.whereObserved({ type, value });
    const byOrg = new Map<string, OrganizationImpact>();
    for (const o of observations) {
      if (!o.organizationId) continue;
      const r = byOrg.get(o.organizationId) ?? { organizationId: o.organizationId, observations: 0, assets: 0, identities: 0 };
      r.observations += o.count;
      if (ASSET_NODE_KINDS.includes(o.node.kind)) r.assets++;
      if (IDENTITY_NODE_KINDS.includes(o.node.kind)) r.identities++;
      if (o.firstSeenAt && (!r.firstSeenAt || o.firstSeenAt < r.firstSeenAt)) r.firstSeenAt = o.firstSeenAt;
      if (o.lastSeenAt && (!r.lastSeenAt || o.lastSeenAt > r.lastSeenAt)) r.lastSeenAt = o.lastSeenAt;
      byOrg.set(o.organizationId, r);
    }
    return [...byOrg.values()].sort((a, b) => b.observations - a.observations || a.organizationId.localeCompare(b.organizationId));
  }

  /** "Which threat actor / malware / campaign is associated with this infrastructure?" */
  async actorsForInfrastructure(ref: NodeRef): Promise<Array<{ node: GraphNode; via: string }>> {
    const n = await this.resolveRef(ref);
    const types: IndicatorType[] =
      n.kind === "ip" ? ["ip"] : n.kind === "domain" ? ["domain"] : n.kind === "url" ? ["url"] : n.kind === "hash" ? (n.key.length === 64 ? ["sha256"] : n.key.length === 40 ? ["sha1"] : ["md5"]) : [];
    const indicatorNodes: GraphNode[] = [];
    if (n.kind === "indicator") indicatorNodes.push(n);
    for (const t of types) {
      for (const org of new Set([n.organizationId, null])) indicatorNodes.push(...(await this.store.findNodes({ kind: "indicator", key: `${t}:${n.key}`, organizationId: org })));
    }
    if (indicatorNodes.length === 0) return [];
    const attr = await this.store.edgesOf(indicatorNodes.map((i) => i.id), { direction: "out", edgeKinds: ["attributed_to"] });
    const nodes = await this.store.getNodes(attr.map((e) => e.to));
    const labelOf = new Map(indicatorNodes.map((i) => [i.id, i.label]));
    return nodes
      .map((t) => ({ node: t, via: `indicator ${labelOf.get(attr.find((e) => e.to === t.id)!.from) ?? ""}`.trim() }))
      .sort((a, b) => a.node.kind.localeCompare(b.node.kind) || a.node.label.localeCompare(b.node.label));
  }

  /**
   * "What is the blast radius of this compromised node?" — everything an attacker controlling
   * it could reach within `depth` attacker steps (attack-movement semantics, see
   * attack-semantics.ts). `assumeExploitable` (default true) treats every reachable host as
   * exploitable (worst case); false requires an exploitable open vulnerability.
   */
  async blastRadius(ref: NodeRef, depth = 3, options: { assumeExploitable?: boolean; exploitabilityThreshold?: number; maxNodes?: number; edgeKinds?: readonly EdgeKind[] } = {}): Promise<BlastRadius> {
    const root = await this.resolveRef(ref);
    const maxDepth = Math.max(1, Math.min(depth, 8));
    const maxNodes = options.maxNodes ?? 2000;
    const assume = options.assumeExploitable ?? true;
    const threshold = options.exploitabilityThreshold ?? 0.3;
    const rules = rulesFor(options.edgeKinds ?? DEFAULT_ATTACK_EDGE_KINDS);
    const kinds = [...new Set(rules.map((r) => r.edgeKind))];
    const visited = new Map<string, { node: GraphNode; depth: number; via: string }>();
    const seen = new Set([root.id]);
    let frontier: GraphNode[] = [root];
    let truncated = false;
    for (let d = 1; d <= maxDepth && frontier.length > 0 && !truncated; d++) {
      const byId = new Map(frontier.map((n) => [n.id, n]));
      const hop = await this.store.edgesOf([...byId.keys()], { direction: "both", edgeKinds: kinds });
      const candidates: Array<{ fromId: string; toId: string; rule: AttackStepRule }> = [];
      for (const e of hop) {
        for (const rule of rules) {
          if (rule.edgeKind !== e.kind) continue;
          const [fromId, toId] = rule.direction === "forward" ? [e.from, e.to] : [e.to, e.from];
          if (byId.has(fromId) && !seen.has(toId)) candidates.push({ fromId, toId, rule });
        }
      }
      const nodes = new Map((await this.store.getNodes([...new Set(candidates.map((c) => c.toId))])).map((n) => [n.id, n]));
      const exploitable = assume ? null : await this.exploitabilityOf([...nodes.keys()]);
      const next: GraphNode[] = [];
      for (const c of candidates) {
        const to = nodes.get(c.toId);
        const from = byId.get(c.fromId);
        if (!to || !from || seen.has(to.id)) continue;
        if (c.rule.appliesTo && !c.rule.appliesTo(from, to)) continue;
        if (c.rule.gated && exploitable && (exploitable.get(to.id) ?? 0) < threshold) continue;
        if (visited.size >= maxNodes) {
          truncated = true;
          break;
        }
        seen.add(to.id);
        visited.set(to.id, { node: to, depth: d, via: `${c.rule.technique} from ${from.label}` });
        next.push(to);
      }
      frontier = next;
    }
    const nodes = [...visited.values()];
    const byKind: Partial<Record<NodeKind, number>> = {};
    for (const v of nodes) byKind[v.node.kind] = (byKind[v.node.kind] ?? 0) + 1;
    return {
      root,
      depth: maxDepth,
      total: nodes.length,
      byKind,
      nodes,
      crownJewels: nodes.filter((v) => isCrownJewel(v.node)).map((v) => v.node),
      privilegedIdentities: nodes.filter((v) => IDENTITY_NODE_KINDS.includes(v.node.kind) && isPrivileged(v.node)).length,
      truncated,
    };
  }

  /**
   * "Which incidents share infrastructure, identity, malware, techniques or indicators with
   * this one?" `scope: "tenant"` also matches the same natural keys in other organizations
   * of the tenant (MSSP cross-customer campaign view).
   */
  async incidentsSharing(incidentId: string, options: { scope?: "organization" | "tenant"; categories?: SharedCategory[] } = {}): Promise<SharedIncident[]> {
    const scope = options.scope ?? "organization";
    const [inc] = await this.store.findNodes({ kind: "incident", key: incidentId.toLowerCase(), limit: 1 });
    if (!inc) throw new GraphError("not_found", `Incident ${incidentId} not linked in the graph`);
    const involved = await this.store.edgesOf([inc.id], { direction: "out", edgeKinds: ["involves"] });
    const entities = await this.store.getNodes(involved.map((e) => e.to));
    const allowed = options.categories ? new Set(options.categories) : null;
    const shared = new Map<string, { incident: GraphNode; shared: SharedIncident["shared"]; score: number }>();
    for (const ent of entities) {
      const category = sharedCategory(ent.kind);
      if (!category || (allowed && !allowed.has(category))) continue;
      const equivalents = scope === "tenant" && ent.organizationId !== null ? await this.store.findNodes({ kind: ent.kind, key: ent.key, limit: 1000 }) : [ent];
      const backEdges = await this.store.edgesOf(equivalents.map((n) => n.id), { direction: "in", edgeKinds: ["involves"] });
      const incidents = await this.store.getNodes(backEdges.map((e) => e.from).filter((id) => id !== inc.id));
      for (const other of incidents) {
        if (other.kind !== "incident") continue;
        if (scope === "organization" && other.organizationId !== inc.organizationId) continue;
        const s = shared.get(other.id) ?? { incident: other, shared: [], score: 0 };
        if (!s.shared.some((x) => x.kind === ent.kind && x.key === ent.key)) {
          s.shared.push({ kind: ent.kind, key: ent.key, label: ent.label, category });
          s.score += CATEGORY_WEIGHT[category];
        }
        shared.set(other.id, s);
      }
    }
    return [...shared.values()].sort((a, b) => b.score - a.score || b.shared.length - a.shared.length || a.incident.label.localeCompare(b.incident.label));
  }

  /** "Which vulnerable internet-facing systems can reach critical assets?" */
  async exposedVulnerableReachingCritical(organizationId: string, options: { maxHops?: number; exploitabilityThreshold?: number } = {}): Promise<Array<{ asset: GraphNode; exploitability: number; reaches: GraphNode[] }>> {
    const threshold = options.exploitabilityThreshold ?? 0.3;
    const maxHops = options.maxHops ?? 4;
    const exposed = await this.store.findNodes({ organizationId, kind: ASSET_NODE_KINDS, propEquals: { internetFacing: true }, limit: 1000 });
    const exploitability = await this.exploitabilityOf(exposed.map((n) => n.id));
    const out: Array<{ asset: GraphNode; exploitability: number; reaches: GraphNode[] }> = [];
    for (const asset of exposed) {
      const e = exploitability.get(asset.id) ?? 0;
      if (e < threshold) continue;
      const reach = await this.store.neighbors(asset.id, { direction: "out", edgeKinds: ["can_reach", "connected_to"], nodeKinds: ASSET_NODE_KINDS, depth: maxHops, limit: 2000 });
      const critical = reach.nodes.map((r) => r.node).filter((n) => {
        const c = nodeCriticality(n);
        return c === "high" || c === "crown_jewel";
      });
      if (critical.length > 0) out.push({ asset, exploitability: e, reaches: critical });
    }
    return out.sort((a, b) => b.reaches.length - a.reaches.length || b.exploitability - a.exploitability);
  }

  /**
   * Load the attack surface of an organization for the Attack-Path Engine: BFS from the
   * internet entry node (and internet-facing assets) over attack-traversable edges, plus the
   * vulnerability, control and threat-intel context of every visited node.
   */
  async loadAttackSurface(organizationId: string, options: { maxDepth?: number; maxNodes?: number; edgeKinds?: readonly EdgeKind[]; includeIntel?: boolean } = {}): Promise<Subgraph & { truncated: boolean }> {
    const maxDepth = options.maxDepth ?? 8;
    const maxNodes = options.maxNodes ?? 5000;
    const rules = rulesFor(options.edgeKinds ?? DEFAULT_ATTACK_EDGE_KINDS);
    const kinds = [...new Set(rules.map((r) => r.edgeKind))];
    const entries = [
      ...(await this.store.findNodes({ organizationId, kind: "internet", limit: 10 })),
      ...(await this.store.findNodes({ organizationId, kind: ASSET_NODE_KINDS, propEquals: { internetFacing: true }, limit: 1000 })),
    ];
    const ids = new Set(entries.map((n) => n.id));
    let frontier = [...ids];
    let truncated = false;
    for (let d = 0; d < maxDepth && frontier.length > 0 && !truncated; d++) {
      const fs = new Set(frontier);
      const hop = await this.store.edgesOf(frontier, { direction: "both", edgeKinds: kinds });
      const next: string[] = [];
      for (const e of hop) {
        for (const rule of rules) {
          if (rule.edgeKind !== e.kind) continue;
          const [fromId, toId] = rule.direction === "forward" ? [e.from, e.to] : [e.to, e.from];
          if (fs.has(fromId) && !ids.has(toId)) {
            if (ids.size >= maxNodes) {
              truncated = true;
              break;
            }
            ids.add(toId);
            next.push(toId);
          }
        }
      }
      frontier = next;
    }
    const contextKinds: EdgeKind[] = ["has_vulnerability", "mitigated_by"];
    const context = await this.store.edgesOf([...ids], { direction: "out", edgeKinds: contextKinds });
    for (const e of context) ids.add(e.to);
    if (options.includeIntel ?? true) {
      const intel = await this.store.edgesOf([...ids], { direction: "in", edgeKinds: ["observed_on"] });
      const intelNodes = await this.store.getNodes(intel.map((e) => e.from));
      for (const n of intelNodes) if (n.kind === "indicator") ids.add(n.id);
    }
    const sub = await this.store.subgraph([...ids]);
    return { ...sub, truncated };
  }

  // ─── Resolution helpers ───────────────────────────────────────────────────

  /** Resolve a node reference; natural-key refs are created when `create` is true. */
  async resolveRef(ref: NodeRef, create = false): Promise<GraphNode> {
    if (typeof ref === "string") {
      const n = await this.store.getNode(ref);
      if (!n) throw new GraphError("not_found", `Graph node ${ref} not found`);
      return n;
    }
    if (ASSET_NODE_KINDS.includes(ref.kind) && ref.organizationId) {
      const found = await this.findAssetByKey(ref.organizationId, ref.key);
      if (found) return found;
    }
    const n = await this.store.getNodeByKey(ref.organizationId, ref.kind, ref.key);
    if (n) return n;
    if (!create) throw new GraphError("not_found", `Graph node ${ref.kind}:${ref.key} not found`);
    return this.store.upsertNode({ organizationId: ref.organizationId, kind: ref.kind, key: ref.key });
  }

  /**
   * Asset entity resolution for an event: strong identifiers first (platform asset id, agent
   * id, cloud instance id — matched against props of any asset kind), then the hostname key,
   * then a new node keyed by the best available identifier. New aliases are merged into the
   * resolved node's props so later events with only one identifier resolve to the same node.
   */
  private async resolveEventAsset(event: CanonicalEvent): Promise<GraphNode | null> {
    const a = event.asset;
    if (!a) return null;
    const org = event.organizationId;
    const found = await this.findAsset(org, {
      ...(a.id ? { id: a.id } : {}),
      ...(a.agentId ? { agentId: a.agentId } : {}),
      ...(a.cloudInstanceId ? { cloudInstanceId: a.cloudInstanceId } : {}),
      ...(a.hostname ? { hostname: a.hostname } : {}),
    });
    const key = found?.key ?? assetKey(a);
    if (!key) return null;
    const kind: NodeKind = found?.kind ?? (a.cloudInstanceId && event.source.kind === "cloud" ? "cloud_asset" : "endpoint");
    const props: Record<string, unknown> = {
      assetId: a.id,
      agentId: a.agentId?.toLowerCase(),
      cloudInstanceId: a.cloudInstanceId?.toLowerCase(),
      hostname: a.hostname,
      hostKey: a.hostname ? (normalizeHostname(a.hostname) ?? undefined) : undefined,
      os: a.os,
    };
    if (a.ip && a.ip.length > 0) {
      const merged = new Set([...(Array.isArray(found?.props.ips) ? (found!.props.ips as string[]) : []), ...a.ip.map((i) => normalizeIp(i)).filter((i): i is string => i !== null)]);
      props.ips = [...merged].slice(0, 32);
    }
    if (a.mac && a.mac.length > 0) props.macs = a.mac.map((m) => m.toLowerCase()).slice(0, 16);
    const n = await this.store.upsertNode({ organizationId: org, kind, key, label: found?.label ?? assetLabel(a, key), props }, { observedAt: event.timestamp });
    this.remember(org, n, { id: a.id, agentId: a.agentId, cloudInstanceId: a.cloudInstanceId, hostname: a.hostname });
    return n;
  }

  private async findAsset(org: string, ids: { id?: string; agentId?: string; cloudInstanceId?: string; hostname?: string }): Promise<GraphNode | null> {
    const probes: Array<[string, string, () => Promise<GraphNode | null>]> = [];
    if (ids.id) probes.push(["id", ids.id.toLowerCase(), () => this.firstAsset(org, { propEquals: { assetId: ids.id! } })]);
    if (ids.agentId) probes.push(["agent", ids.agentId.toLowerCase(), () => this.firstAsset(org, { propEquals: { agentId: ids.agentId!.toLowerCase() } })]);
    if (ids.cloudInstanceId) probes.push(["cloud", ids.cloudInstanceId.toLowerCase(), () => this.firstAsset(org, { propEquals: { cloudInstanceId: ids.cloudInstanceId!.toLowerCase() } })]);
    const host = ids.hostname ? normalizeHostname(ids.hostname) : null;
    if (host) probes.push(["host", host, async () => (await this.firstAsset(org, { key: host })) ?? this.firstAsset(org, { propEquals: { hostKey: host } })]);
    for (const [kind, value, probe] of probes) {
      const cached = this.aliasCache.get(`${org}|${kind}|${value}`);
      if (cached) {
        const n = await this.store.getNode(cached);
        if (n) return n;
        this.aliasCache.delete(`${org}|${kind}|${value}`);
      }
      const n = await probe();
      if (n) {
        this.cache(`${org}|${kind}|${value}`, n.id);
        return n;
      }
    }
    return null;
  }

  private async firstAsset(org: string, q: { key?: string; propEquals?: Record<string, string> }): Promise<GraphNode | null> {
    const [n] = await this.store.findNodes({ organizationId: org, kind: ASSET_NODE_KINDS, ...q, limit: 1 });
    return n ?? null;
  }

  private async findAssetByKey(org: string, key: string): Promise<GraphNode | null> {
    const [n] = await this.store.findNodes({ organizationId: org, kind: ASSET_NODE_KINDS, key, limit: 1 });
    return n ?? null;
  }

  private remember(org: string, n: GraphNode, ids: { id?: string | undefined; agentId?: string | undefined; cloudInstanceId?: string | undefined; hostname?: string | undefined }): void {
    if (ids.id) this.cache(`${org}|id|${ids.id.toLowerCase()}`, n.id);
    if (ids.agentId) this.cache(`${org}|agent|${ids.agentId.toLowerCase()}`, n.id);
    if (ids.cloudInstanceId) this.cache(`${org}|cloud|${ids.cloudInstanceId.toLowerCase()}`, n.id);
    const host = ids.hostname ? normalizeHostname(ids.hostname) : null;
    if (host) this.cache(`${org}|host|${host}`, n.id);
  }

  private cache(key: string, nodeId: string): void {
    if (this.cacheSize <= 0) return;
    this.aliasCache.delete(key);
    this.aliasCache.set(key, nodeId);
    while (this.aliasCache.size > this.cacheSize) {
      const oldest = this.aliasCache.keys().next().value;
      if (oldest === undefined) break;
      this.aliasCache.delete(oldest);
    }
  }

  private async hostsOfProcess(processId: string): Promise<GraphNode[]> {
    const e = await this.store.edgesOf([processId], { direction: "out", edgeKinds: ["runs_on"] });
    return this.store.getNodes(e.map((x) => x.to));
  }

  private async hostsOfFile(fileId: string): Promise<GraphNode[]> {
    const e = await this.store.edgesOf([fileId], { direction: "in", edgeKinds: ["contains"] });
    return (await this.store.getNodes(e.map((x) => x.from))).filter((n) => ASSET_NODE_KINDS.includes(n.kind));
  }

  /** Max exploitability of each node's open vulnerabilities (or explicit `exploitability` prop). */
  async exploitabilityOf(nodeIds: readonly string[]): Promise<Map<string, number>> {
    const out = new Map<string, number>();
    if (nodeIds.length === 0) return out;
    const nodes = await this.store.getNodes(nodeIds);
    for (const n of nodes) {
      const explicit = propNumber(n.props, "exploitability");
      if (explicit !== undefined) out.set(n.id, explicit);
    }
    const vulnEdges = (await this.store.edgesOf(nodeIds, { direction: "out", edgeKinds: ["has_vulnerability"] })).filter((e) => isOpenVulnerabilityEdge(e.props));
    const vulns = new Map((await this.store.getNodes(vulnEdges.map((e) => e.to))).map((n) => [n.id, n]));
    for (const e of vulnEdges) {
      const v = vulns.get(e.to);
      if (!v) continue;
      out.set(e.from, Math.max(out.get(e.from) ?? 0, vulnerabilityNodeExploitability(v)));
    }
    return out;
  }
}

const CATEGORY_WEIGHT: Record<SharedCategory, number> = { indicator: 3, malware: 3, threat_actor: 3, identity: 2.5, infrastructure: 2, technique: 1 };

function sharedCategory(kind: NodeKind): SharedCategory | null {
  switch (kind) {
    case "ip":
    case "domain":
    case "url":
    case "certificate":
    case "endpoint":
    case "server":
    case "cloud_asset":
    case "container":
    case "application":
    case "saas_app":
    case "data_store":
    case "k8s_resource":
      return "infrastructure";
    case "user":
    case "identity":
    case "service_account":
    case "credential":
    case "group":
      return "identity";
    case "malware":
    case "hash":
    case "file":
      return "malware";
    case "technique":
      return "technique";
    case "indicator":
      return "indicator";
    case "threat_actor":
    case "campaign":
      return "threat_actor";
    default:
      return null;
  }
}

function strengthOf(relations: string[]): number {
  let best = 9;
  for (const r of relations) {
    for (const [k, v] of Object.entries(ACCESS_STRENGTH)) if (r.startsWith(k) && v < best) best = v;
    if (r.startsWith("ran processes")) best = Math.min(best, ACCESS_STRENGTH.process!);
  }
  return best;
}

function assetNodeKind(kind: AssetKind): NodeKind {
  switch (kind) {
    case "endpoint":
      return "endpoint";
    case "server":
    case "domain_controller":
    case "network_device":
    case "external_host":
      return "server";
    case "database":
    case "data_store":
    case "cloud_storage":
      return "data_store";
    case "cloud_instance":
      return "cloud_asset";
    case "container":
      return "container";
    case "kubernetes_cluster":
      return "k8s_resource";
    case "application":
      return "application";
    case "saas_app":
      return "saas_app";
  }
}

function truncate(s: string | undefined): string | undefined {
  return s === undefined ? undefined : s.length > MAX_COMMAND_LINE ? `${s.slice(0, MAX_COMMAND_LINE)}…` : s;
}

function safeHost(url: string): string | null {
  try {
    return normalizeDomain(new URL(url).hostname);
  } catch {
    return null;
  }
}

