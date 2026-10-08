import type { EngineDefinition } from "@bloody/contracts";
import { Plug, RefreshCw, Settings2 } from "lucide-react";
import { useState } from "react";
import { errorMessage } from "../../api/client";
import { useIntegrations, useSyncIntegration } from "../../api/hooks";
import type { IntegrationStatus, IntegrationView } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, type BadgeTone } from "../../components/Badge";
import { Button } from "../../components/Button";
import { ErrorState } from "../../components/ErrorState";
import { RelativeTime } from "../../components/RelativeTime";
import { SkeletonText } from "../../components/Skeleton";
import { engineByKey, MODE_LABELS } from "../../lib/engines";
import { formatNumber } from "../../lib/format";
import { IntegrationDialog } from "./IntegrationDialog";

export const STATUS_TONE: Record<IntegrationStatus, BadgeTone> = { healthy: "success", degraded: "warning", error: "danger", pending: "info", disabled: "neutral", unknown: "outline" };

export function IntegrationStatusBadge({ integration }: { integration: IntegrationView }) {
  const status: IntegrationStatus = integration.enabled ? integration.status : "disabled";
  return (
    <Badge size="xs" tone={STATUS_TONE[status] ?? "outline"} title={integration.lastError ?? undefined}>
      {status}
    </Badge>
  );
}

/** One configured connection: health, last sync, volume, sync / configure. */
export function IntegrationRow({ integration, engine, onConfigure }: { integration: IntegrationView; engine: EngineDefinition | undefined; onConfigure?: () => void }) {
  const session = useSession();
  const sync = useSyncIntegration();
  const canWrite = session.can("integration:write", integration.organizationId);
  return (
    <li className="flex flex-wrap items-center gap-2 px-3 py-2" data-testid="integration-row">
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-medium text-fg">{integration.name}</span>
        <span className="block truncate text-2xs text-fg-subtle">
          {engine?.name ?? integration.engine}
          {integration.endpoint ? ` · ${integration.endpoint}` : ""} · {integration.organizationId ? (session.organizationName(integration.organizationId) ?? "Organization") : "Tenant-wide"}
        </span>
        {integration.lastError ? <span className="block truncate text-2xs text-sev-critical" title={integration.lastError}>{integration.lastError}</span> : null}
      </span>
      <IntegrationStatusBadge integration={integration} />
      {integration.eventsLast24h !== null && integration.eventsLast24h !== undefined ? <span className="text-2xs text-fg-muted">{formatNumber(integration.eventsLast24h)} events/24h</span> : null}
      <span className="text-2xs text-fg-subtle">{integration.lastSyncAt ? <>synced <RelativeTime value={integration.lastSyncAt} /></> : "never synced"}</span>
      {canWrite ? (
        <>
          <Button size="xs" icon={RefreshCw} loading={sync.isPending} disabled={!integration.enabled} onClick={() => sync.mutate(integration.id)} title="Sync now">
            Sync
          </Button>
          {onConfigure ? (
            <Button size="xs" icon={Settings2} onClick={onConfigure}>
              Configure
            </Button>
          ) : null}
        </>
      ) : null}
      {sync.isError ? <span className="w-full text-2xs text-sev-critical">{errorMessage(sync.error)}</span> : null}
      {sync.isSuccess ? <span className="w-full text-2xs text-healthy">{sync.data?.message ?? "Sync started."}</span> : null}
    </li>
  );
}

/**
 * Health of the engines feeding a view (sensors, log sources, scanners, intel feeds): every
 * configured connection plus a Connect action for engines not configured yet.
 */
export function IntegrationStatusList({ engines, showUnconfigured = true }: { engines: string[]; showUnconfigured?: boolean }) {
  const session = useSession();
  const integrations = useIntegrations({ enabled: session.canAnywhere("integration:read") });
  const [dialog, setDialog] = useState<{ engine: EngineDefinition; existing: IntegrationView | null } | null>(null);
  const canWrite = session.canAnywhere("integration:write");
  if (!session.canAnywhere("integration:read")) return <p className="p-3 text-sm text-fg-muted">You don't have access to integration health.</p>;
  if (integrations.isPending) return <div className="p-3"><SkeletonText lines={3} /></div>;
  if (integrations.isError) return <ErrorState error={integrations.error} compact onRetry={() => void integrations.refetch()} />;
  const defs = engines.map((k) => engineByKey(k)).filter((e): e is EngineDefinition => e !== undefined);
  const configured = (integrations.data ?? []).filter((i) => engines.includes(i.engine));
  const missing = defs.filter((d) => !configured.some((i) => i.engine === d.key));
  return (
    <>
      <ul className="divide-y divide-line" aria-label="Integrations">
        {configured.map((i) => {
          const def = engineByKey(i.engine);
          return <IntegrationRow key={i.id} integration={i} engine={def} onConfigure={def ? () => setDialog({ engine: def, existing: i }) : undefined} />;
        })}
        {showUnconfigured
          ? missing.map((d) => (
              <li key={d.key} className="flex flex-wrap items-center gap-2 px-3 py-2">
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-fg">{d.name}</span>
                  <span className="block truncate text-2xs text-fg-subtle">
                    {d.role} · {MODE_LABELS[d.mode]}
                  </span>
                </span>
                <Badge size="xs" tone="outline">
                  Not connected
                </Badge>
                {canWrite ? (
                  <Button size="xs" variant="primary" icon={Plug} onClick={() => setDialog({ engine: d, existing: null })}>
                    Connect
                  </Button>
                ) : null}
              </li>
            ))
          : null}
      </ul>
      {configured.length === 0 && !showUnconfigured ? <p className="p-3 text-sm text-fg-muted">No connections configured.</p> : null}
      {dialog ? <IntegrationDialog engine={dialog.engine} existing={dialog.existing} onClose={() => setDialog(null)} /> : null}
    </>
  );
}
