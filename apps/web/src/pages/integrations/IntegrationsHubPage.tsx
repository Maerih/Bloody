import { ENGINES, EXCLUDED_KEYED_SERVICES, MODULES, OPEN_INTEL_SOURCES, type EngineDefinition, type ModuleKey } from "@bloody/contracts";
import { clsx } from "clsx";
import { Blocks, ExternalLink, Plug, Puzzle, Search, ShieldCheck, Sigma, Workflow } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { useIntegrations } from "../../api/hooks";
import type { IntegrationView } from "../../api/types";
import { ORG_PARAM, useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { Checkbox, Input, Select } from "../../components/Form";
import { PageHeader } from "../../components/PageHeader";
import { CardSkeleton } from "../../components/Skeleton";
import { StatTile } from "../../components/StatTile";
import { Tabs } from "../../components/Tabs";
import { IntegrationDialog } from "../../features/integrations/IntegrationDialog";
import { IntegrationRow, IntegrationStatusBadge } from "../../features/integrations/IntegrationStatusList";
import { KpiGrid } from "../../features/modules/ModuleWorkspace";
import { DetectionRulesView } from "../../features/siem/DetectionRulesView";
import { PlaybooksView } from "../../features/soar/PlaybooksView";
import { engineByKey, LAYER_LABELS, LAYER_ORDER, MODE_LABELS, moduleName } from "../../lib/engines";

type HubTab = "engines" | "connected" | "content" | "playbooks";

const RISK_TONE = { low: "success", medium: "warning", high: "danger" } as const;

function EngineCard({ engine, connections, onConfigure, canWrite }: { engine: EngineDefinition; connections: IntegrationView[]; onConfigure: (existing: IntegrationView | null) => void; canWrite: boolean }) {
  const featured = engine.key === "copilot";
  return (
    <article className={clsx("flex h-full flex-col rounded border bg-surface p-3 shadow-card", featured ? "border-primary/50" : "border-line")} data-testid="engine-card" aria-label={engine.name}>
      <header className="flex items-start gap-2">
        <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded bg-surface-3 text-fg-muted" aria-hidden>
          <Puzzle size={15} />
        </span>
        <div className="min-w-0 flex-1">
          <h3 className="flex items-center gap-1.5 truncate text-md font-semibold text-fg">
            {engine.name}
            {engine.core ? <Badge size="xs" tone="info">Core</Badge> : <Badge size="xs" tone="outline">Optional</Badge>}
          </h3>
          <p className="text-xs text-fg-muted">{engine.role}</p>
        </div>
        <a href={engine.homepage} target="_blank" rel="noopener noreferrer" className="text-fg-subtle hover:text-fg" aria-label={`${engine.name} homepage`}>
          <ExternalLink size={13} />
        </a>
      </header>
      <div className="mt-2 flex flex-wrap gap-1">
        <Badge size="xs" tone="outline" title="SPDX licence expression">
          {engine.license}
        </Badge>
        <Badge size="xs" tone={RISK_TONE[engine.licenseRisk]} title={engine.licenseNotes}>
          licence risk: {engine.licenseRisk}
        </Badge>
        <Badge size="xs">{MODE_LABELS[engine.mode]}</Badge>
      </div>
      <p className="mt-2 line-clamp-3 text-2xs text-fg-subtle" title={engine.licenseNotes}>
        {engine.licenseNotes}
      </p>
      <div className="mt-2 flex flex-wrap gap-1" aria-label="Modules powered">
        {engine.powers.map((m) => (
          <Badge key={m} size="xs" tone="purple">
            {moduleName(m)}
          </Badge>
        ))}
      </div>
      <div className="mt-auto pt-3">
        {connections.length > 0 ? (
          <ul className="mb-2 space-y-1">
            {connections.map((c) => (
              <li key={c.id} className="flex items-center gap-1.5 text-xs">
                <IntegrationStatusBadge integration={c} />
                <span className="min-w-0 flex-1 truncate">{c.name}</span>
                {canWrite ? (
                  <button type="button" className="text-primary hover:underline" onClick={() => onConfigure(c)}>
                    Configure
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        ) : null}
        {canWrite ? (
          <Button size="sm" variant={connections.length === 0 ? "primary" : "secondary"} icon={Plug} onClick={() => onConfigure(null)} className="w-full">
            {connections.length === 0 ? `Connect ${engine.name}` : "Add connection"}
          </Button>
        ) : connections.length === 0 ? (
          <p className="text-xs text-fg-subtle">Not connected</p>
        ) : null}
      </div>
    </article>
  );
}

/**
 * Integrations Hub: the open-source engine catalogue (licence, licence risk, integration mode,
 * modules powered) with configure / health / sync, plus the detection-content and playbook
 * libraries. Engines always run as separate, unmodified services.
 */
export default function IntegrationsHubPage() {
  const session = useSession();
  const location = useLocation();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const integrations = useIntegrations({ enabled: session.canAnywhere("integration:read") });
  const tab: HubTab = location.pathname.startsWith("/hub/content") ? "content" : location.pathname.startsWith("/hub/playbooks") ? "playbooks" : location.pathname === "/integrations" && params.get("view") !== "catalog" ? "connected" : "engines";
  const [q, setQ] = useState("");
  const [layer, setLayer] = useState<string>("");
  const [module, setModule] = useState<string>("");
  const [connectedOnly, setConnectedOnly] = useState(false);
  const [dialog, setDialog] = useState<{ engine: EngineDefinition; existing: IntegrationView | null } | null>(null);
  const canWrite = session.canAnywhere("integration:write");

  // ?engine=<key> (from "Connect <engine>" empty states) opens the configure dialog.
  const engineParam = params.get("engine");
  useEffect(() => {
    if (!engineParam) return;
    const def = engineByKey(engineParam);
    if (def) setDialog({ engine: def, existing: null });
  }, [engineParam]);
  const closeDialog = () => {
    setDialog(null);
    if (engineParam) {
      const next = new URLSearchParams(params);
      next.delete("engine");
      setParams(next, { replace: true });
    }
  };

  const byEngine = useMemo(() => {
    const m = new Map<string, IntegrationView[]>();
    for (const i of integrations.data ?? []) m.set(i.engine, [...(m.get(i.engine) ?? []), i]);
    return m;
  }, [integrations.data]);

  const filtered = useMemo(() => {
    const term = q.trim().toLowerCase();
    return ENGINES.filter((e) => !layer || e.layer === layer)
      .filter((e) => !module || e.powers.includes(module as ModuleKey))
      .filter((e) => !connectedOnly || (byEngine.get(e.key)?.length ?? 0) > 0)
      .filter((e) => !term || `${e.name} ${e.role} ${e.license} ${e.key}`.toLowerCase().includes(term));
  }, [q, layer, module, connectedOnly, byEngine]);

  const all = integrations.data ?? [];
  const healthy = all.filter((i) => i.enabled && i.status === "healthy").length;
  const failing = all.filter((i) => i.enabled && (i.status === "error" || i.status === "degraded")).length;
  const copilot = ENGINES.find((e) => e.key === "copilot");

  const go = (t: HubTab) => {
    const org = new URLSearchParams(location.search).get(ORG_PARAM);
    const sp = new URLSearchParams();
    if (org) sp.set(ORG_PARAM, org);
    let pathname = t === "content" ? "/hub/content" : t === "playbooks" ? "/hub/playbooks" : t === "connected" ? "/integrations" : "/hub/engines";
    if (t === "engines" && location.pathname === "/integrations") {
      pathname = "/integrations";
      sp.set("view", "catalog");
    }
    const search = sp.toString();
    navigate({ pathname, search: search ? `?${search}` : "" });
  };

  return (
    <div>
      <PageHeader
        title={location.pathname === "/integrations" ? "Integrations" : "Hub & Marketplace"}
        subtitle="Connect open-source engines as separate, unmodified services. Bloody drives them over their APIs, event streams or file drops and normalizes everything into one data model."
      >
        <Tabs<HubTab>
          ariaLabel="Hub sections"
          idPrefix="hub"
          value={tab}
          onChange={go}
          tabs={[
            { id: "connected", label: "Connected", icon: Plug, count: integrations.data ? all.length : null },
            { id: "engines", label: "Engine catalog", icon: Blocks, count: ENGINES.length },
            { id: "content", label: "Detection content", icon: Sigma },
            { id: "playbooks", label: "Playbook library", icon: Workflow },
          ]}
        />
      </PageHeader>

      {tab === "content" ? <DetectionRulesView /> : null}
      {tab === "playbooks" ? <PlaybooksView library /> : null}

      {tab === "connected" ? (
        <div className="space-y-3">
          <KpiGrid>
            <StatTile label="Connections" value={integrations.data ? all.length : null} loading={integrations.isPending} icon={Plug} />
            <StatTile label="Healthy" value={integrations.data ? healthy : null} loading={integrations.isPending} tone="healthy" />
            <StatTile label="Degraded / failing" value={integrations.data ? failing : null} loading={integrations.isPending} tone={failing > 0 ? "critical" : "default"} />
            <StatTile label="Disabled" value={integrations.data ? all.filter((i) => !i.enabled).length : null} loading={integrations.isPending} />
          </KpiGrid>
          <Card title="Connected engines" count={integrations.data ? all.length : null} padded={false} actions={<Button size="xs" onClick={() => go("engines")}>Browse catalog</Button>}>
            {!session.canAnywhere("integration:read") ? (
              <EmptyState compact title="You don't have access to integrations" />
            ) : integrations.isPending ? (
              <div className="p-3">
                <CardSkeleton rows={3} />
              </div>
            ) : integrations.isError ? (
              <ErrorState error={integrations.error} onRetry={() => void integrations.refetch()} compact />
            ) : all.length === 0 ? (
              <EmptyState icon={Plug} title="Nothing connected yet" description="Start with an endpoint engine (Wazuh), a network sensor (Zeek / Suricata) and your identity provider." action={<Button size="sm" variant="primary" onClick={() => go("engines")}>Browse the engine catalog</Button>} />
            ) : (
              <ul className="divide-y divide-line">
                {all.map((i) => {
                  const def = engineByKey(i.engine);
                  return <IntegrationRow key={i.id} integration={i} engine={def} onConfigure={def ? () => setDialog({ engine: def, existing: i }) : undefined} />;
                })}
              </ul>
            )}
          </Card>
        </div>
      ) : null}

      {tab === "engines" ? (
        <div className="space-y-4">
          {copilot ? (
            <Card title="SOCFortress CoPilot integration" subtitle="Bring an existing CoPilot SOC hub into Bloody" actions={<Badge tone="warning">AGPL-3.0 · separate service</Badge>}>
              <div className="grid grid-cols-1 gap-3 md:grid-cols-[minmax(0,1fr)_280px]">
                <div className="space-y-2 text-sm text-fg-muted">
                  <p>Bloody syncs CoPilot customers → organizations, agents, alerts and cases → incidents over CoPilot's REST API, so MSSPs can migrate or run both side by side. No CoPilot code is copied or linked.</p>
                  <p className="text-xs">{copilot.licenseNotes}</p>
                </div>
                <div className="space-y-2">
                  {(byEngine.get("copilot") ?? []).map((c) => (
                    <div key={c.id} className="flex items-center gap-2 text-sm">
                      <IntegrationStatusBadge integration={c} />
                      <span className="truncate">{c.name}</span>
                    </div>
                  ))}
                  {canWrite ? (
                    <Button variant="primary" icon={Plug} className="w-full" onClick={() => setDialog({ engine: copilot, existing: byEngine.get("copilot")?.[0] ?? null })}>
                      {(byEngine.get("copilot")?.length ?? 0) > 0 ? "Configure CoPilot sync" : "Connect CoPilot"}
                    </Button>
                  ) : null}
                </div>
              </div>
            </Card>
          ) : null}
          <div className="flex flex-wrap items-center gap-2 rounded border border-line bg-surface px-3 py-2 shadow-card">
            <label className="relative min-w-[220px] flex-1">
              <Search size={13} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-fg-subtle" aria-hidden />
              <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search engines, licences…" className="h-7 pl-7" aria-label="Search engines" />
            </label>
            <Select value={layer} onChange={(e) => setLayer(e.target.value)} className="h-7 w-48" aria-label="Layer">
              <option value="">All layers</option>
              {LAYER_ORDER.map((l) => (
                <option key={l} value={l}>
                  {LAYER_LABELS[l]}
                </option>
              ))}
            </Select>
            <Select value={module} onChange={(e) => setModule(e.target.value)} className="h-7 w-48" aria-label="Module">
              <option value="">All modules</option>
              {MODULES.map((m) => (
                <option key={m.key} value={m.key}>
                  {m.name}
                </option>
              ))}
            </Select>
            <Checkbox label="Connected only" checked={connectedOnly} onChange={(e) => setConnectedOnly(e.target.checked)} />
          </div>
          {LAYER_ORDER.map((l) => {
            const items = filtered.filter((e) => e.layer === l);
            if (items.length === 0) return null;
            return (
              <section key={l} aria-label={LAYER_LABELS[l]}>
                <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">
                  {LAYER_LABELS[l]} <span className="font-normal">({items.length})</span>
                </h2>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
                  {items.map((e) => (
                    <EngineCard key={e.key} engine={e} connections={byEngine.get(e.key) ?? []} canWrite={canWrite} onConfigure={(existing) => setDialog({ engine: e, existing })} />
                  ))}
                </div>
              </section>
            );
          })}
          {filtered.length === 0 ? <EmptyState compact title="No engine matches these filters" /> : null}
          <Card title="Key-less intelligence sources" info="Free sources used by default. Commercial API-keyed services are excluded from the default stack.">
            <ul className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
              {OPEN_INTEL_SOURCES.map((s) => (
                <li key={s.key} className="flex items-start gap-2 text-sm">
                  <ShieldCheck size={14} className="mt-0.5 shrink-0 text-healthy" aria-hidden />
                  <span>
                    <a href={s.url} target="_blank" rel="noopener noreferrer" className="font-medium text-heading hover:underline">
                      {s.name}
                    </a>
                    <span className="block text-2xs text-fg-subtle">{s.license}</span>
                  </span>
                </li>
              ))}
            </ul>
            <p className="mt-3 text-xs text-fg-muted">Not used by default (paid API keys): {EXCLUDED_KEYED_SERVICES.join(", ")}.</p>
          </Card>
        </div>
      ) : null}

      {dialog ? <IntegrationDialog engine={dialog.engine} existing={dialog.existing} onClose={closeDialog} /> : null}
    </div>
  );
}
