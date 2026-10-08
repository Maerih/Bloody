import type { Asset, Identity } from "@bloody/contracts";
import { Fingerprint, Link2Off, Lock, Network, Server, Sparkles, Target } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useIncidentGraph, useIntelMatches } from "../../api/hooks";
import type { IncidentDetail } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { RiskScore } from "../../components/RiskScore";
import { SkeletonText } from "../../components/Skeleton";
import { hrefForEntity } from "../../lib/entityLinks";
import { humanize } from "../../lib/format";
import { GraphWorkbench } from "../graph/GraphWorkbench";
import { useGraphExplorer } from "../graph/useGraphExplorer";
import { RequestActionDialog } from "../response/RequestActionDialog";
import { identityName } from "../identities/identityUtils";

/** Shown in incident-derived tabs when the investigation has no linked incident. */
export function NoIncidentState({ what }: { what: string }) {
  return (
    <EmptyState
      compact
      icon={Link2Off}
      title={`No linked incident — ${what} unavailable`}
      description="Alerts, entities, graph and telemetry panels are scoped by the incident this investigation explains. Open the investigation from an incident to populate them."
      action={
        <ButtonLink size="sm" to="/incidents">
          Browse incidents
        </ButtonLink>
      }
    />
  );
}

function EntityRow({ icon: Icon, title, subtitle, href, badges, actions }: { icon: typeof Server; title: string; subtitle?: string | null; href: string; badges?: ReactNode; actions?: ReactNode }) {
  return (
    <li className="flex flex-wrap items-center gap-2 px-3 py-2">
      <Icon size={14} className="text-fg-muted" aria-hidden />
      <span className="min-w-0 flex-1">
        <Link to={href} className="block truncate font-medium text-heading hover:underline">
          {title}
        </Link>
        {subtitle ? <span className="block truncate text-xs text-fg-subtle">{subtitle}</span> : null}
      </span>
      {badges}
      {actions}
    </li>
  );
}

/** Assets, identities and indicators involved in the incident, with pivots and containment. */
export function EntitiesPanel({ incident }: { incident: IncidentDetail }) {
  const session = useSession();
  const matches = useIntelMatches({ incidentId: incident.id, organizationId: incident.organizationId }, { enabled: session.can("intel:read", incident.organizationId) });
  const [respond, setRespond] = useState<{ kind: "asset"; target: Asset } | { kind: "identity"; target: Identity } | null>(null);
  const canRespond = session.can("response:request", incident.organizationId);
  const canAi = session.isModuleEnabled("ai_soc") && session.can("ai:use", incident.organizationId);
  const assets = incident.assets ?? [];
  const identities = incident.identities ?? [];
  const indicators = useMemo(() => {
    const byValue = new Map<string, { value: string; type: string; severity: string | null; count: number }>();
    for (const m of matches.data?.items ?? []) {
      const value = m.indicator?.value ?? m.value ?? m.indicatorId;
      const cur = byValue.get(value) ?? { value, type: m.indicator?.type ?? "indicator", severity: m.indicator?.severity ?? null, count: 0 };
      cur.count += 1;
      byValue.set(value, cur);
    }
    return [...byValue.values()];
  }, [matches.data]);

  const missingAssets = incident.assetIds.length - assets.length;
  const missingIdentities = incident.identityIds.length - identities.length;

  return (
    <div className="space-y-4">
      <section>
        <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">Assets ({incident.assetIds.length})</h3>
        {incident.assetIds.length === 0 ? (
          <p className="text-sm text-fg-subtle">No assets involved.</p>
        ) : (
          <ul className="divide-y divide-line rounded border border-line">
            {assets.map((a) => (
              <EntityRow
                key={a.id}
                icon={Server}
                title={a.hostname ?? a.name}
                subtitle={[humanize(a.kind), a.ipAddresses.slice(0, 2).join(", "), a.os].filter(Boolean).join(" · ")}
                href={hrefForEntity("asset", a.id)}
                badges={
                  <>
                    {a.criticality === "crown_jewel" ? <Badge size="xs" tone="danger">Crown jewel</Badge> : null}
                    {a.internetFacing ? <Badge size="xs" tone="warning">Internet-facing</Badge> : null}
                    <RiskScore score={a.riskScore} size="sm" explanationHref={hrefForEntity("asset", a.id)} />
                  </>
                }
                actions={
                  <span className="flex gap-1">
                    {canAi ? <ButtonLink size="xs" icon={Sparkles} to={`/ai?context=${encodeURIComponent(`asset:${a.id}`)}`}>Ask AI</ButtonLink> : null}
                    <ButtonLink size="xs" icon={Network} to={`/graph?q=${encodeURIComponent(a.hostname ?? a.name)}`}>Graph</ButtonLink>
                    {canRespond ? (
                      <Button size="xs" variant="danger" icon={Lock} onClick={() => setRespond({ kind: "asset", target: a })}>
                        Contain
                      </Button>
                    ) : null}
                  </span>
                }
              />
            ))}
            {missingAssets > 0 ? <li className="px-3 py-2 text-xs text-fg-subtle">{missingAssets} more asset(s) — open the incident for the full list.</li> : null}
          </ul>
        )}
      </section>
      <section>
        <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">Identities ({incident.identityIds.length})</h3>
        {incident.identityIds.length === 0 ? (
          <p className="text-sm text-fg-subtle">No identities involved.</p>
        ) : (
          <ul className="divide-y divide-line rounded border border-line">
            {identities.map((i) => (
              <EntityRow
                key={i.id}
                icon={Fingerprint}
                title={identityName(i)}
                subtitle={`${humanize(i.kind)} · ${i.provider} · ${i.principal}`}
                href={hrefForEntity("identity", i.id)}
                badges={
                  <>
                    {i.privileged ? <Badge size="xs" tone="warning">Privileged</Badge> : null}
                    {i.mfaEnabled ? null : <Badge size="xs" tone="danger">No MFA</Badge>}
                    <RiskScore score={i.riskScore} size="sm" label="Identity risk" />
                  </>
                }
                actions={
                  canRespond ? (
                    <Button size="xs" variant="danger" icon={Lock} onClick={() => setRespond({ kind: "identity", target: i })}>
                      Contain
                    </Button>
                  ) : null
                }
              />
            ))}
            {missingIdentities > 0 ? <li className="px-3 py-2 text-xs text-fg-subtle">{missingIdentities} more identit{missingIdentities === 1 ? "y" : "ies"} — open the incident for the full list.</li> : null}
          </ul>
        )}
      </section>
      <section>
        <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">Indicators observed ({indicators.length})</h3>
        {matches.isPending && session.can("intel:read", incident.organizationId) ? (
          <SkeletonText lines={2} />
        ) : indicators.length === 0 ? (
          <p className="text-sm text-fg-subtle">No threat-intelligence indicator matched this incident's activity.</p>
        ) : (
          <ul className="divide-y divide-line rounded border border-line">
            {indicators.map((i) => (
              <EntityRow key={i.value} icon={Target} title={i.value} subtitle={`${humanize(i.type)} · ${i.count} match(es)`} href={`/cti/indicators?q=${encodeURIComponent(i.value)}`} badges={i.severity ? <Badge size="xs" tone={i.severity === "critical" || i.severity === "high" ? "danger" : "warning"}>{i.severity}</Badge> : null} />
            ))}
          </ul>
        )}
      </section>
      {respond ? (
        <RequestActionDialog
          open
          onClose={() => setRespond(null)}
          organizationId={incident.organizationId}
          incidentId={incident.id}
          actions={respond.kind === "asset" ? ["isolate_endpoint", "release_endpoint", "collect_evidence", "run_yara_scan", "kill_process", "quarantine_file"] : ["disable_identity", "revoke_sessions", "revoke_token"]}
          targets={respond.kind === "asset" ? { asset: [{ id: respond.target.id, label: respond.target.hostname ?? respond.target.name }] } : { identity: [{ id: respond.target.id, label: identityName(respond.target) }] }}
        />
      ) : null}
    </div>
  );
}

/** The incident's subgraph in the shared graph workbench (expand, contextual actions). */
export function IncidentGraphPanel({ incident }: { incident: IncidentDetail }) {
  const graph = useIncidentGraph(incident.id);
  const explorer = useGraphExplorer();
  const loaded = useRef<string | null>(null);
  useEffect(() => {
    if (graph.data && loaded.current !== incident.id) {
      loaded.current = incident.id;
      explorer.load(graph.data, graph.data.nodes.filter((n) => n.kind === "incident").map((n) => n.id));
    }
  }, [graph.data, incident.id, explorer]);
  if (graph.isPending) return <SkeletonText lines={8} />;
  if (graph.isError) return <ErrorState error={graph.error} onRetry={() => void graph.refetch()} compact />;
  return (
    <GraphWorkbench
      explorer={explorer}
      height={480}
      incidentId={incident.id}
      toolbar={
        <ButtonLink size="xs" icon={Network} to={`/graph?incident=${encodeURIComponent(incident.id)}`}>
          Open in explorer
        </ButtonLink>
      }
      emptyState={<EmptyState compact icon={Network} title="The incident has no graph entities yet" description="Entities appear as alerts are correlated into this incident." />}
    />
  );
}
