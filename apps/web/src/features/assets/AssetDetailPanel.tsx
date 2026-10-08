import type { Asset, GraphNode } from "@bloody/contracts";
import { Bug, Fingerprint, Lock, Network, Route, Siren, Sparkles } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useAsset, useAssetRisk, useAttackPaths, useGraphNeighbors, useGraphSearch } from "../../api/hooks";
import type { AssetDetail } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, SeverityBadge, StatusBadge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { AttackPathChain } from "../../components/AttackPathChain";
import { DescriptionList } from "../../components/DescriptionList";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { ASSET_NODE_KINDS, IDENTITY_NODE_KINDS, nodeKindMeta } from "../../components/graph/nodeKinds";
import { RelativeTime } from "../../components/RelativeTime";
import { RiskFactorBars } from "../../components/RiskFactorBars";
import { RiskScore } from "../../components/RiskScore";
import { SkeletonText } from "../../components/Skeleton";
import { pathsTouchingAsset } from "../../lib/attackPaths";
import { hrefForEntity } from "../../lib/entityLinks";
import { formatDate, humanize } from "../../lib/format";
import { RequestActionDialog } from "../response/RequestActionDialog";

const ACCESS_EDGES = new Set(["has_access_to", "admin_of", "logged_into", "authenticates_as", "owns", "stores_credential_for"]);

function Section({ title, icon: Icon, count, children, actions }: { title: string; icon?: typeof Bug; count?: number | null; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="border-b border-line px-4 py-3 last:border-b-0">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">
          {Icon ? <Icon size={12} aria-hidden /> : null}
          {title}
          {count !== undefined && count !== null ? <span className="font-normal">({count})</span> : null}
        </h3>
        {actions}
      </div>
      {children}
    </section>
  );
}

/** The asset's Security Graph node: graph search by hostname/name, matched on props.assetId. */
function useAssetGraphNode(asset: Asset | undefined): { node: GraphNode | null; loading: boolean } {
  const q = asset ? (asset.hostname ?? asset.name) : "";
  const search = useGraphSearch({ q, kinds: ASSET_NODE_KINDS, limit: 10, organizationId: asset?.organizationId ?? null }, { enabled: Boolean(asset) && q.length >= 2 });
  const node = useMemo(() => {
    if (!asset || !search.data) return null;
    return search.data.find((n) => n.props?.assetId === asset.id) ?? search.data.find((n) => n.key.toLowerCase() === (asset.hostname ?? "").toLowerCase()) ?? null;
  }, [asset, search.data]);
  return { node, loading: search.isLoading };
}

/**
 * Asset drill-down: explained risk, vulnerabilities, identities with access (graph), attack
 * paths through the asset, alerts/incidents and pivots (graph, AI, isolate).
 */
export function AssetDetailPanel({ assetId }: { assetId: string }) {
  const asset = useAsset(assetId);
  if (asset.isPending) {
    return (
      <div className="p-4">
        <SkeletonText lines={8} />
      </div>
    );
  }
  if (asset.isError) return <ErrorState error={asset.error} onRetry={() => void asset.refetch()} />;
  return <AssetDetailBody asset={asset.data} />;
}

function AssetDetailBody({ asset }: { asset: AssetDetail }) {
  const session = useSession();
  const org = asset.organizationId;
  const risk = useAssetRisk(session.can("risk:read", org) ? asset.id : null);
  const graphNode = useAssetGraphNode(session.can("graph:read", org) ? asset : undefined);
  const neighbors = useGraphNeighbors(graphNode.node?.id, { depth: 1, limit: 200 });
  const paths = useAttackPaths({ organizationId: org }, { enabled: session.can("risk:read", org) });
  const [isolate, setIsolate] = useState(false);

  const identities = useMemo(() => {
    const g = neighbors.data;
    if (!g || !graphNode.node) return [];
    const self = graphNode.node.id;
    const byId = new Map(g.nodes.map((n) => [n.id, n]));
    const out = new Map<string, { node: GraphNode; relations: Set<string> }>();
    for (const e of g.edges) {
      if (!ACCESS_EDGES.has(e.kind)) continue;
      const other = e.from === self ? e.to : e.to === self ? e.from : null;
      const node = other ? byId.get(other) : undefined;
      if (!node || !(IDENTITY_NODE_KINDS as string[]).includes(node.kind)) continue;
      const entry = out.get(node.id) ?? { node, relations: new Set<string>() };
      entry.relations.add(e.kind.replace(/_/g, " "));
      out.set(node.id, entry);
    }
    return [...out.values()];
  }, [neighbors.data, graphNode.node]);

  const assetPaths = useMemo(() => pathsTouchingAsset(paths.data?.paths ?? [], asset.id), [paths.data, asset.id]);
  const isEndpoint = ["endpoint", "server", "domain_controller", "database", "cloud_instance"].includes(asset.kind);
  const agent = asset.agents?.[0];
  const canAi = session.isModuleEnabled("ai_soc") && session.can("ai:use", org);

  return (
    <div>
      <div className="space-y-2 border-b border-line px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="outline">{humanize(asset.kind)}</Badge>
          <Badge tone={asset.criticality === "crown_jewel" ? "danger" : asset.criticality === "high" ? "warning" : "neutral"}>{humanize(asset.criticality)}</Badge>
          {asset.internetFacing ? <Badge tone="warning">Internet-facing</Badge> : null}
          {agent ? <StatusBadge status={agent.status === "protected" ? "active" : agent.status} /> : null}
          <span className="text-sm text-fg-subtle">
            Last seen <RelativeTime value={asset.lastSeenAt} />
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          {canAi ? (
            <ButtonLink size="sm" variant="primary" icon={Sparkles} to={`/ai?context=${encodeURIComponent(`asset:${asset.id}`)}`}>
              Ask AI
            </ButtonLink>
          ) : null}
          <ButtonLink size="sm" icon={Network} to={graphNode.node ? `/graph?node=${encodeURIComponent(graphNode.node.id)}` : `/graph?q=${encodeURIComponent(asset.hostname ?? asset.name)}`}>
            Graph pivot
          </ButtonLink>
          <ButtonLink size="sm" icon={Siren} to={`/siem/search?q=${encodeURIComponent(`asset.id:${asset.id}`)}`}>
            Events
          </ButtonLink>
          {isEndpoint && session.can("response:request", org) ? (
            <Button size="sm" variant="danger" icon={Lock} onClick={() => setIsolate(true)}>
              {agent?.status === "isolated" ? "Release / respond" : "Isolate endpoint"}
            </Button>
          ) : null}
        </div>
      </div>

      <Section title="Risk explanation">
        <div className="mb-2 flex items-center gap-3">
          <RiskScore score={risk.data?.score ?? asset.riskScore} factors={risk.data?.factors} summary={risk.data?.summary} modelVersion={risk.data?.modelVersion} size="lg" label="Asset risk" />
          {risk.isError ? <span className="text-xs text-fg-subtle">{errorMessage(risk.error)}</span> : null}
        </div>
        {risk.isLoading ? <SkeletonText lines={3} /> : risk.data ? <RiskFactorBars factors={risk.data.factors} likelihood={risk.data.likelihood} impact={risk.data.impact} score={risk.data.score} summary={risk.data.summary} modelVersion={risk.data.modelVersion} compact /> : null}
      </Section>

      <Section title="Details">
        <DescriptionList
          items={[
            { label: "Hostname", value: asset.hostname },
            { label: "IP addresses", value: asset.ipAddresses.join(", ") || null },
            { label: "OS", value: asset.os },
            { label: "Owner", value: asset.owner },
            { label: "Organization", value: session.organizationName(org) },
            { label: "Agent", value: agent ? `${agent.engine} ${agent.version} · ${humanize(agent.status)}` : null },
            { label: "Tags", value: asset.tags.length > 0 ? asset.tags.join(", ") : null, wide: true },
          ]}
        />
      </Section>

      <Section title="Vulnerabilities" icon={Bug} count={asset.vulnerabilities?.length ?? null} actions={<ButtonLink size="xs" to={`/vm/vulnerabilities?asset=${encodeURIComponent(asset.id)}`}>All</ButtonLink>}>
        {asset.vulnerabilities === null ? (
          <p className="text-sm text-fg-subtle">You don't have access to vulnerability data.</p>
        ) : (asset.vulnerabilities ?? []).length === 0 ? (
          <p className="text-sm text-fg-subtle">No open vulnerabilities.</p>
        ) : (
          <ul className="divide-y divide-line rounded border border-line">
            {asset.vulnerabilities!.slice(0, 12).map((v) => (
              <li key={v.id} className="flex items-center gap-2 px-2.5 py-1.5 text-sm">
                <SeverityBadge severity={v.severity} size="xs" />
                <span className="font-mono text-xs">{v.cve ?? "—"}</span>
                <span className="min-w-0 flex-1 truncate">{v.title}</span>
                {v.knownExploited ? <Badge size="xs" tone="danger">KEV</Badge> : null}
                {v.epss !== null ? <span className="text-xs text-fg-subtle">EPSS {(v.epss * 100).toFixed(1)}%</span> : null}
                <RiskScore score={v.riskScore} size="sm" />
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Identities with access" icon={Fingerprint} count={graphNode.node ? identities.length : null}>
        {!session.can("graph:read", org) ? (
          <p className="text-sm text-fg-subtle">You don't have access to the Security Graph.</p>
        ) : graphNode.loading || neighbors.isLoading ? (
          <SkeletonText lines={2} />
        ) : !graphNode.node ? (
          <p className="text-sm text-fg-subtle">This asset is not in the Security Graph yet.</p>
        ) : identities.length === 0 ? (
          <p className="text-sm text-fg-subtle">No identities have recorded access to this asset.</p>
        ) : (
          <ul className="space-y-1">
            {identities.map(({ node, relations }) => {
              const Icon = nodeKindMeta(node.kind).icon;
              const identityId = typeof node.props?.identityId === "string" ? node.props.identityId : null;
              return (
                <li key={node.id} className="flex items-center gap-2 text-sm">
                  <Icon size={13} aria-hidden className="text-fg-muted" />
                  {identityId ? (
                    <Link to={hrefForEntity("identity", identityId)} className="text-heading hover:underline">
                      {node.label}
                    </Link>
                  ) : (
                    <Link to={`/graph?node=${encodeURIComponent(node.id)}`} className="text-heading hover:underline">
                      {node.label}
                    </Link>
                  )}
                  <span className="text-xs text-fg-subtle">{[...relations].join(", ")}</span>
                  {node.props?.privileged === true ? <Badge size="xs" tone="warning">privileged</Badge> : null}
                </li>
              );
            })}
          </ul>
        )}
      </Section>

      <Section title="Attack paths" icon={Route} count={paths.data ? assetPaths.length : null} actions={<ButtonLink size="xs" to="/attack-paths">All paths</ButtonLink>}>
        {paths.isLoading ? (
          <SkeletonText lines={2} />
        ) : paths.isError ? (
          <p className="text-sm text-fg-subtle">{errorMessage(paths.error)}</p>
        ) : assetPaths.length === 0 ? (
          <p className="text-sm text-fg-subtle">No discovered attack path runs through this asset.</p>
        ) : (
          <ul className="space-y-2">
            {assetPaths.slice(0, 5).map((p) => (
              <li key={p.id} className="rounded border border-line p-2">
                <div className="mb-1 flex items-center gap-2 text-xs">
                  <RiskScore score={p.risk.score} factors={p.risk.factors} summary={p.risk.summary} size="sm" label="Path risk" />
                  <span className="text-fg-muted">{p.risk.summary}</span>
                </div>
                <AttackPathChain path={p} compact />
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Incidents & alerts" icon={Siren} count={(asset.incidents?.length ?? 0) + (asset.alerts?.length ?? 0)}>
        {(asset.incidents ?? []).length === 0 && (asset.alerts ?? []).length === 0 ? (
          <EmptyState compact title="No incidents or alerts involve this asset" />
        ) : (
          <ul className="divide-y divide-line rounded border border-line">
            {(asset.incidents ?? []).slice(0, 10).map((i) => (
              <li key={i.id} className="flex items-center gap-2 px-2.5 py-1.5 text-sm">
                <SeverityBadge severity={i.severity} size="xs" />
                <Link to={hrefForEntity("incident", i.id)} className="min-w-0 flex-1 truncate text-heading hover:underline">
                  #{i.number} {i.title}
                </Link>
                <StatusBadge status={i.status} size="xs" />
                <span className="text-xs text-fg-subtle">{formatDate(i.detectedAt)}</span>
              </li>
            ))}
            {(asset.alerts ?? []).slice(0, 10).map((a) => (
              <li key={a.id} className="flex items-center gap-2 px-2.5 py-1.5 text-sm">
                <SeverityBadge severity={a.severity} size="xs" />
                <Link to={hrefForEntity("alert", a.id)} className="min-w-0 flex-1 truncate hover:underline">
                  {a.title}
                </Link>
                <span className="text-xs text-fg-subtle">{a.source}</span>
                <RelativeTime value={a.lastSeenAt} className="text-xs text-fg-subtle" />
              </li>
            ))}
          </ul>
        )}
      </Section>

      {isolate ? (
        <RequestActionDialog
          open
          onClose={() => setIsolate(false)}
          organizationId={org}
          actions={["isolate_endpoint", "release_endpoint", "collect_evidence", "run_yara_scan", "kill_process", "quarantine_file"]}
          defaultAction={agent?.status === "isolated" ? "release_endpoint" : "isolate_endpoint"}
          targets={{ asset: [{ id: asset.id, label: asset.hostname ?? asset.name }] }}
        />
      ) : null}
    </div>
  );
}
