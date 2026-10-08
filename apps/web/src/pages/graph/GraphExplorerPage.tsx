import type { GraphNode, NodeKind } from "@bloody/contracts";
import { clsx } from "clsx";
import { Eraser, Network, Search, Siren } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useGraphSearch, useIncident, useIncidentGraph } from "../../api/hooks";
import { errorMessage } from "../../api/client";
import { useSession } from "../../app/session";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { EmptyState } from "../../components/EmptyState";
import { Input } from "../../components/Form";
import { nodeKindMeta, PIVOT_KINDS } from "../../components/graph/nodeKinds";
import { PageHeader } from "../../components/PageHeader";
import { SkeletonText } from "../../components/Skeleton";
import { GraphWorkbench } from "../../features/graph/GraphWorkbench";
import { useGraphExplorer } from "../../features/graph/useGraphExplorer";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import { hrefForEntity } from "../../lib/entityLinks";

/**
 * Security Graph explorer: search any entity, expand neighbors, and pivot with contextual
 * actions. Supports ?q= (prefilled search), ?node=<id> (open a node) and ?incident=<id>
 * (load an incident's subgraph).
 */
export default function GraphExplorerPage() {
  const session = useSession();
  const [params, setParams] = useSearchParams();
  const explorer = useGraphExplorer();
  const [q, setQ] = useState(params.get("q") ?? "");
  const [kinds, setKinds] = useState<NodeKind[]>([]);
  const term = useDebouncedValue(q, 250);
  const search = useGraphSearch({ q: term, kinds, limit: 25 }, { enabled: session.can("graph:read") || session.canAnywhere("graph:read") });
  const incidentId = params.get("incident");
  const incident = useIncident(incidentId);
  const incidentGraph = useIncidentGraph(incidentId);
  const nodeParam = params.get("node");
  const loadedIncident = useRef<string | null>(null);
  const openedNode = useRef<string | null>(null);

  // ?incident=<id> → the incident's subgraph.
  useEffect(() => {
    if (incidentId && incidentGraph.data && loadedIncident.current !== incidentId) {
      loadedIncident.current = incidentId;
      const roots = incidentGraph.data.nodes.filter((n) => n.kind === "incident").map((n) => n.id);
      explorer.load(incidentGraph.data, roots);
    }
  }, [incidentId, incidentGraph.data, explorer]);

  // ?node=<id> → open that node and its neighbors.
  useEffect(() => {
    if (!nodeParam || openedNode.current === nodeParam) return;
    openedNode.current = nodeParam;
    void explorer.open({ id: nodeParam, kind: "indicator", key: nodeParam, label: nodeParam, organizationId: null, props: {} } as GraphNode).then(() => undefined);
  }, [nodeParam, explorer]);

  const toggleKind = (k: NodeKind) => setKinds((cur) => (cur.includes(k) ? cur.filter((x) => x !== k) : [...cur, k]));

  if (!session.canAnywhere("graph:read")) {
    return (
      <div>
        <PageHeader title="Security Graph" />
        <div className="rounded border border-line bg-surface shadow-card">
          <EmptyState icon={Network} title="You don't have access to the Security Graph" description="Ask an administrator for the graph:read permission." />
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="Security Graph"
        subtitle="Pivot across users, identities, endpoints, processes, files, hashes, domains, IPs and threat actors. Double-click to expand, right-click for actions."
        breadcrumbs={[{ label: "XDR", href: "/xdr" }, { label: "Security Graph" }]}
        actions={
          <Button
            size="sm"
            icon={Eraser}
            onClick={() => {
              explorer.reset();
              loadedIncident.current = null;
              openedNode.current = null;
              const next = new URLSearchParams(params);
              next.delete("node");
              next.delete("incident");
              setParams(next, { replace: true });
            }}
            disabled={explorer.graph.nodes.length === 0}
          >
            Clear canvas
          </Button>
        }
      />
      {incidentId ? (
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded border border-line bg-surface px-3 py-2 text-sm shadow-card">
          <Siren size={14} className="text-sev-high" aria-hidden />
          {incident.data ? (
            <span>
              Showing the graph of incident{" "}
              <Link to={hrefForEntity("incident", incidentId)} className="font-medium text-primary hover:underline">
                #{incident.data.number} {incident.data.title}
              </Link>
            </span>
          ) : (
            <span>Loading incident graph…</span>
          )}
          {incidentGraph.isError ? <span className="text-sev-critical">{errorMessage(incidentGraph.error)}</span> : null}
        </div>
      ) : null}
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[300px_minmax(0,1fr)]">
        <Card title="Find an entity" padded={false}>
          <div className="space-y-2 p-3">
            <label className="relative block">
              <Search size={14} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-fg-subtle" aria-hidden />
              <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Hostname, user, IP, domain, hash, CVE…" className="pl-7" aria-label="Search the Security Graph" autoFocus />
            </label>
            <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by kind">
              {PIVOT_KINDS.map((k) => {
                const meta = nodeKindMeta(k);
                const on = kinds.includes(k);
                return (
                  <button
                    key={k}
                    type="button"
                    aria-pressed={on}
                    onClick={() => toggleKind(k)}
                    className={clsx("inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-2xs", on ? "border-primary bg-primary-soft text-primary" : "border-line text-fg-muted hover:text-fg")}
                  >
                    <meta.icon size={10} aria-hidden /> {meta.label}
                  </button>
                );
              })}
            </div>
          </div>
          <div className="max-h-[480px] overflow-y-auto border-t border-line scrollbar-thin" aria-live="polite">
            {term.trim().length < 2 ? (
              <p className="p-3 text-sm text-fg-muted">Type at least two characters to search the graph of {session.organization ? session.organization.name : "all organizations"}.</p>
            ) : search.isPending ? (
              <div className="p-3">
                <SkeletonText lines={4} />
              </div>
            ) : search.isError ? (
              <p className="p-3 text-sm text-sev-critical">{errorMessage(search.error)}</p>
            ) : (search.data ?? []).length === 0 ? (
              <EmptyState compact title="No matching entities" description="The graph fills in as connected sources report assets, identities, processes and network activity." />
            ) : (
              <ul className="divide-y divide-line" aria-label="Search results">
                {search.data!.map((n) => {
                  const meta = nodeKindMeta(n.kind);
                  const onCanvas = explorer.graph.nodes.some((g) => g.id === n.id);
                  return (
                    <li key={n.id}>
                      <button type="button" onClick={() => void explorer.open(n)} className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-surface-2">
                        <span className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-white" style={{ background: meta.color }} aria-hidden>
                          <meta.icon size={12} />
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-sm font-medium text-fg">{n.label}</span>
                          <span className="block truncate text-2xs uppercase tracking-wide text-fg-subtle">
                            {meta.label}
                            {n.organizationId && !session.organizationId ? ` · ${session.organizationName(n.organizationId) ?? ""}` : ""}
                          </span>
                        </span>
                        {onCanvas ? <span className="text-2xs text-healthy">on canvas</span> : null}
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </Card>
        <GraphWorkbench
          explorer={explorer}
          height={600}
          {...(incidentId ? { incidentId } : {})}
          emptyState={
            incidentId && incidentGraph.isPending ? (
              <div className="p-4">
                <SkeletonText lines={6} />
              </div>
            ) : (
              <ConnectEngineEmptyState
                icon={Network}
                title="Start from an entity"
                description="Search on the left to place a node on the canvas. The Security Graph is built from every connected source — endpoints, identities, network sensors, cloud and threat intelligence."
                engines={["wazuh", "zeek", "keycloak"]}
              />
            )
          }
        />
      </div>
    </div>
  );
}
