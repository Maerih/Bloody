import { clsx } from "clsx";
import { ChevronRight, Gauge } from "lucide-react";
import { Link } from "react-router-dom";
import { useExposureSummary } from "../../api/hooks";
import { RAIL_MODULES } from "../../app/navigation";
import { useSession } from "../../app/session";
import { Card } from "../../components/Card";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { ErrorState } from "../../components/ErrorState";
import { NarrativeCard } from "../../components/NarrativeCard";
import { RiskFactorBars } from "../../components/RiskFactorBars";
import { RiskScore } from "../../components/RiskScore";
import { CardSkeleton } from "../../components/Skeleton";
import { severityMetaForScore } from "../../lib/severity";

function modulePath(module: string | null | undefined): string | null {
  if (!module) return null;
  return RAIL_MODULES.find((m) => m.module === module)?.path ?? null;
}

/**
 * Unified exposure score: one explained number across external surface, vulnerabilities,
 * identity, cloud, SaaS, misconfiguration, attack paths and active threat — never just a
 * vulnerability count. Each domain links to the module that fixes it.
 */
export function ExposureBreakdown() {
  const session = useSession();
  const exposure = useExposureSummary({ enabled: session.canAnywhere("risk:read") });
  if (exposure.isPending) return <CardSkeleton rows={6} />;
  if (exposure.isError) {
    return (
      <div className="rounded border border-line bg-surface shadow-card">
        <ErrorState error={exposure.error} onRetry={() => void exposure.refetch()} />
      </div>
    );
  }
  const e = exposure.data;
  const components = e.components ?? [];
  const hasSignal = components.some((c) => c.score > 0) || (e.factors ?? []).length > 0;
  return (
    <div className="space-y-3" data-testid="exposure-breakdown">
      {e.narrative ? <NarrativeCard narrative={e.narrative} /> : null}
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[320px_minmax(0,1fr)]">
        <Card title="Exposure score" info="0–100, higher is worse. Likelihood (domain exposure, combined so independent signals reinforce but saturate) × impact (business baseline, crown-jewel reachability), reduced by compensating controls.">
          <div className="flex flex-col items-center gap-2 py-2">
            <RiskScore score={e.score} factors={e.factors} summary={e.summary} modelVersion={e.modelVersion} size="lg" label="Exposure score" />
            {e.summary ? <p className="text-center text-sm text-fg-muted">{e.summary}</p> : null}
            {e.inherentScore !== null && e.inherentScore !== undefined && Math.abs(e.inherentScore - e.score) >= 0.5 ? (
              <p className="text-center text-xs text-fg-subtle">Without compensating controls it would be {e.inherentScore.toFixed(0)}.</p>
            ) : null}
          </div>
          {e.organizations && e.organizations.length > 1 ? (
            <div className="mt-2 border-t border-line pt-2">
              <h3 className="mb-1 text-2xs font-semibold uppercase tracking-wide text-fg-subtle">By organization</h3>
              <ul className="space-y-1">
                {e.organizations.slice(0, 10).map((o) => (
                  <li key={o.organizationId} className="flex items-center gap-2 text-sm">
                    <span className="min-w-0 flex-1 truncate">{o.organizationName ?? session.organizationName(o.organizationId)}</span>
                    <RiskScore score={o.score} size="sm" />
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </Card>
        <Card title="Exposure by domain" count={components.length} info="Each domain's exposure 0–100 with the drivers behind it." padded={false}>
          {components.length === 0 ? (
            <p className="p-3 text-sm text-fg-muted">No domain breakdown was returned.</p>
          ) : (
            <ul className="divide-y divide-line" aria-label="Exposure domains">
              {components.map((c) => {
                const href = modulePath(c.module);
                const meta = severityMetaForScore(c.score);
                const body = (
                  <>
                    <div className="flex items-center gap-2">
                      <span className="min-w-0 flex-1 truncate text-sm font-medium text-fg">{c.label}</span>
                      <span className={clsx("text-sm font-semibold tabular-nums", c.score > 0 ? meta.text : "text-fg-subtle")}>{c.score.toFixed(0)}</span>
                      {href ? <ChevronRight size={13} className="text-fg-subtle" aria-hidden /> : null}
                    </div>
                    <div className="mt-1 h-1.5 rounded bg-surface-3" role="meter" aria-label={`${c.label} exposure`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(c.score)}>
                      <div className={clsx("h-1.5 rounded", meta.bg)} style={{ width: `${Math.max(0, Math.min(100, c.score))}%` }} />
                    </div>
                    {c.drivers && c.drivers.length > 0 ? <p className="mt-1 text-xs text-fg-muted">{c.drivers.join(" · ")}</p> : c.score === 0 ? <p className="mt-1 text-xs text-fg-subtle">No exposure signals.</p> : null}
                  </>
                );
                return (
                  <li key={c.key} data-domain={c.key}>
                    {href ? (
                      <Link to={href} className="block px-3 py-2 hover:bg-surface-2">
                        {body}
                      </Link>
                    ) : (
                      <div className="px-3 py-2">{body}</div>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>
      {hasSignal ? (
        <Card title="Why this score" info="Every factor's contribution in points; compensating controls are negative.">
          <RiskFactorBars factors={e.factors ?? []} likelihood={e.likelihood} impact={e.impact} score={e.score} modelVersion={e.modelVersion} />
        </Card>
      ) : (
        <div className="rounded border border-line bg-surface shadow-card">
          <ConnectEngineEmptyState icon={Gauge} title="No exposure signals yet" description="Exposure is computed from assets, vulnerabilities, identities, cloud posture, attack paths and threat intelligence. Connect sources to populate it." engines={["greenbone", "nuclei", "keycloak"]} />
        </div>
      )}
    </div>
  );
}
