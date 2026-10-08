import type { EngineDefinition } from "@bloody/contracts";
import { CalendarClock, Crosshair, Gauge, Plug, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useIntegrations } from "../../api/hooks";
import type { IntegrationView } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { ErrorState } from "../../components/ErrorState";
import { SkeletonText } from "../../components/Skeleton";
import { engineByKey } from "../../lib/engines";
import { daysUntil, formatDate } from "../../lib/format";
import { IntegrationDialog, readScanScope, SCANNING_ENGINES } from "./IntegrationDialog";
import { IntegrationStatusBadge } from "./IntegrationStatusList";

export type AuthorizationState = "valid" | "expiring" | "expired" | "missing";

export function authorizationState(expiresAt: string | null | undefined, now: number = Date.now()): AuthorizationState {
  if (!expiresAt) return "missing";
  const d = daysUntil(expiresAt, now);
  if (d === null) return "missing";
  if (d < 0) return "expired";
  if (d <= 14) return "expiring";
  return "valid";
}

const AUTH_META: Record<AuthorizationState, { label: string; tone: "success" | "warning" | "danger" | "neutral" }> = {
  valid: { label: "Authorized", tone: "success" },
  expiring: { label: "Authorization expiring", tone: "warning" },
  expired: { label: "Authorization expired — scanning blocked", tone: "danger" },
  missing: { label: "No authorization recorded", tone: "danger" },
};

function ScopeCard({ integration, engine, onEdit }: { integration: IntegrationView; engine: EngineDefinition | undefined; onEdit?: () => void }) {
  const scope = readScanScope(integration.config);
  const state = authorizationState(scope?.authorization.expiresAt);
  return (
    <article className="rounded border border-line bg-surface p-3 shadow-card" data-testid="scan-scope-card" aria-label={`${integration.name} scan scope`}>
      <header className="flex flex-wrap items-center gap-2">
        <Crosshair size={14} className="text-fg-muted" aria-hidden />
        <h3 className="min-w-0 flex-1 truncate font-semibold text-fg">{integration.name}</h3>
        <IntegrationStatusBadge integration={integration} />
        <Badge size="xs" tone={AUTH_META[state].tone} icon={state === "valid" ? ShieldCheck : ShieldAlert}>
          {AUTH_META[state].label}
        </Badge>
      </header>
      <p className="mt-0.5 text-2xs text-fg-subtle">{engine?.role}</p>
      {scope ? (
        <div className="mt-2 grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
          <div>
            <h4 className="text-2xs font-semibold uppercase tracking-wide text-fg-subtle">Authorized targets ({scope.targets.length})</h4>
            <ul className="mt-0.5 max-h-28 overflow-y-auto font-mono text-xs scrollbar-thin">
              {scope.targets.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ul>
            {scope.exclusions.length > 0 ? (
              <>
                <h4 className="mt-1.5 text-2xs font-semibold uppercase tracking-wide text-fg-subtle">Exclusions ({scope.exclusions.length})</h4>
                <ul className="font-mono text-xs text-fg-muted">
                  {scope.exclusions.map((t) => (
                    <li key={t}>{t}</li>
                  ))}
                </ul>
              </>
            ) : null}
          </div>
          <dl className="space-y-1.5 text-xs">
            <div className="flex items-center gap-1.5">
              <Gauge size={12} className="text-fg-muted" aria-hidden />
              <dt className="text-fg-muted">Rate limit</dt>
              <dd className="ml-auto font-medium">{scope.ratePerSecond} req/s</dd>
            </div>
            <div className="flex items-center gap-1.5">
              <ShieldCheck size={12} className="text-fg-muted" aria-hidden />
              <dt className="text-fg-muted">Authorization</dt>
              <dd className="ml-auto truncate font-medium" title={scope.authorization.reference}>
                {scope.authorization.reference || "—"}
              </dd>
            </div>
            <div className="flex items-center gap-1.5">
              <dt className="pl-[18px] text-fg-muted">Approved by</dt>
              <dd className="ml-auto font-medium">{scope.authorization.approvedBy || "—"}</dd>
            </div>
            <div className="flex items-center gap-1.5">
              <CalendarClock size={12} className="text-fg-muted" aria-hidden />
              <dt className="text-fg-muted">Expires</dt>
              <dd className={`ml-auto font-medium ${state === "expired" ? "text-sev-critical" : state === "expiring" ? "text-sev-high" : ""}`}>{scope.authorization.expiresAt ? formatDate(scope.authorization.expiresAt) : "—"}</dd>
            </div>
          </dl>
        </div>
      ) : (
        <p className="mt-2 text-sm text-sev-high">No authorized scope is recorded — this scanner must not run until targets, rate limit and written authorization are configured.</p>
      )}
      {onEdit ? (
        <div className="mt-3">
          <Button size="sm" onClick={onEdit}>
            Edit scope & authorization
          </Button>
        </div>
      ) : null}
    </article>
  );
}

/**
 * Scan scope controls for active scanners (Nuclei, Subfinder, Amass, Greenbone): authorized
 * targets, exclusions, rate limit and written authorization with expiry. Every change is audited.
 */
export function ScanScopes() {
  const session = useSession();
  const integrations = useIntegrations({ enabled: session.canAnywhere("integration:read") });
  const [editing, setEditing] = useState<{ engine: EngineDefinition; existing: IntegrationView | null } | null>(null);
  if (integrations.isPending) return <SkeletonText lines={4} />;
  if (integrations.isError) return <ErrorState error={integrations.error} onRetry={() => void integrations.refetch()} />;
  const scanners = (integrations.data ?? []).filter((i) => SCANNING_ENGINES.has(i.engine));
  const canWrite = session.canAnywhere("integration:write");
  if (scanners.length === 0) {
    return (
      <div className="rounded border border-line bg-surface shadow-card">
        <ConnectEngineEmptyState icon={Crosshair} title="No scanner is configured" description="Active discovery and exposure scanning only run against authorized targets within a rate limit. Connect a scanner and record its authorization." engines={["nuclei", "subfinder", "amass"]} extraAction={canWrite ? <Button size="sm" icon={Plug} onClick={() => setEditing({ engine: engineByKey("nuclei")!, existing: null })}>Configure Nuclei</Button> : undefined} />
        {editing ? <IntegrationDialog engine={editing.engine} existing={editing.existing} onClose={() => setEditing(null)} /> : null}
      </div>
    );
  }
  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
      {scanners.map((i) => {
        const engine = engineByKey(i.engine);
        return <ScopeCard key={i.id} integration={i} engine={engine} onEdit={canWrite && engine && session.can("integration:write", i.organizationId) ? () => setEditing({ engine, existing: i }) : undefined} />;
      })}
      {editing ? <IntegrationDialog engine={editing.engine} existing={editing.existing} onClose={() => setEditing(null)} /> : null}
    </div>
  );
}
