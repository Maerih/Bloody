import { Severity, SEVERITY_RANK } from "@bloody/contracts";
import { Crown, DoorOpen, Gauge, Route, Search, Target, Wrench } from "lucide-react";
import { useMemo, useState } from "react";
import { useAttackPaths } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Card } from "../../components/Card";
import { NarrativeCard } from "../../components/NarrativeCard";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { Checkbox, Input, Select } from "../../components/Form";
import { CardSkeleton } from "../../components/Skeleton";
import { StatTile } from "../../components/StatTile";
import { rankRemediations, type RankedRemediation } from "../../lib/attackPaths";
import { formatInteger, humanize } from "../../lib/format";
import { KpiGrid } from "../modules/ModuleWorkspace";
import { AttackPathCard, isCrownJewelTarget, RemediationPriorityList } from "./AttackPathList";

const PAGE = 25;

/**
 * Attack paths from entry points (Internet, phished identities…) to crown jewels, with the
 * explained risk of each path and the greedy remediation ranking ("fix this → breaks N paths").
 * `focus` = "remediation" leads with the remediation plan (ESPM).
 */
export function AttackPathsView({ focus = "paths", targetId, initialCrownOnly = false }: { focus?: "paths" | "remediation"; targetId?: string; initialCrownOnly?: boolean }) {
  const session = useSession();
  const result = useAttackPaths({ ...(targetId ? { targetId } : {}) }, { enabled: session.can("risk:read") || session.canAnywhere("risk:read") });
  const [q, setQ] = useState("");
  const [minSeverity, setMinSeverity] = useState<Severity>("info");
  const [crownOnly, setCrownOnly] = useState(initialCrownOnly);
  const [selectedFix, setSelectedFix] = useState<RankedRemediation | null>(null);
  const [shown, setShown] = useState(PAGE);

  const paths = result.data?.paths;
  const ranked = useMemo(() => rankRemediations(paths ?? [], result.data?.remediations ?? []), [paths, result.data?.remediations]);
  const filtered = useMemo(() => {
    const term = q.trim().toLowerCase();
    return (paths ?? [])
      .filter((p) => SEVERITY_RANK[p.risk.severity] >= SEVERITY_RANK[minSeverity])
      .filter((p) => !crownOnly || isCrownJewelTarget(p))
      .filter((p) => !term || p.nodes.some((n) => n.label.toLowerCase().includes(term)) || p.target.label.toLowerCase().includes(term) || p.entry.label.toLowerCase().includes(term))
      .filter((p) => !selectedFix || selectedFix.pathIds.length === 0 || selectedFix.pathIds.includes(p.id))
      .sort((a, b) => b.risk.score - a.risk.score);
  }, [paths, q, minSeverity, crownOnly, selectedFix]);

  const summary = result.data?.summary;
  const total = summary?.totalPaths ?? paths?.length ?? 0;
  const targets = summary?.targetsAtRisk ?? new Set((paths ?? []).map((p) => p.target.id)).size;
  const entries = summary?.entryPoints ?? new Set((paths ?? []).map((p) => p.entry.id)).size;
  const maxRisk = summary?.maxRiskScore ?? Math.max(0, ...(paths ?? []).map((p) => p.risk.score));
  const crownPaths = (paths ?? []).filter(isCrownJewelTarget).length;

  if (!session.canAnywhere("risk:read")) {
    return <EmptyState icon={Route} title="You don't have access to attack paths" description="Attack paths require the risk:read permission." />;
  }
  if (result.isPending) {
    return (
      <div className="space-y-3">
        <CardSkeleton rows={2} />
        <CardSkeleton rows={6} />
      </div>
    );
  }
  if (result.isError) {
    const needsOrg = session.organizationId === null && (result.error.status === 400 || result.error.status === 422);
    return (
      <div className="rounded border border-line bg-surface shadow-card">
        {needsOrg ? (
          <EmptyState icon={Route} title="Select an organization" description="Attack paths are computed per organization. Pick one in the account switcher to analyze its attack surface." />
        ) : (
          <ErrorState error={result.error} onRetry={() => void result.refetch()} />
        )}
      </div>
    );
  }

  const remediationCard = (
    <Card
      title="Remediation priorities"
      count={ranked.length}
      info="Greedy cut over every discovered path: the first fix breaks the most paths, and together they break all of them. Select one to see the paths it breaks."
      padded={false}
    >
      <RemediationPriorityList items={ranked} totalPaths={total} activeKey={selectedFix?.key ?? null} onSelect={setSelectedFix} />
      {summary?.fixesToBreakAll ? <p className="border-t border-line px-3 py-2 text-xs text-fg-muted">{formatInteger(summary.fixesToBreakAll)} fix(es) break every discovered path.</p> : null}
    </Card>
  );

  return (
    <div className="space-y-3">
      <KpiGrid>
        <StatTile label="Attack paths" value={total} icon={Route} tone={total > 0 ? "high" : "healthy"} hint={summary?.truncated ? "Search budget reached — more may exist" : undefined} />
        <StatTile label="To crown jewels" value={crownPaths} icon={Crown} tone={crownPaths > 0 ? "critical" : "healthy"} />
        <StatTile label="Targets at risk" value={targets} icon={Target} />
        <StatTile label="Entry points" value={entries} icon={DoorOpen} />
        <StatTile label="Highest path risk" value={total > 0 ? maxRisk : null} format={(v) => (v === null || v === undefined ? "—" : v.toFixed(0))} icon={Gauge} tone={maxRisk >= 70 ? "critical" : "default"} />
        <StatTile label="Fixes to break all" value={summary?.fixesToBreakAll ?? (total > 0 ? ranked.length : 0)} icon={Wrench} tone="primary" hint={summary?.shortestPathLength ? `Shortest path: ${summary.shortestPathLength} hops` : undefined} />
      </KpiGrid>

      {result.data?.narrative && total > 0 ? <NarrativeCard narrative={result.data.narrative} /> : null}
      {total === 0 ? (
        <div className="rounded border border-line bg-surface shadow-card">
          <ConnectEngineEmptyState
            icon={Route}
            title="No attack path reaches a protected target"
            description="Paths are computed from the Security Graph: exposed services, exploitable vulnerabilities, identities and their access. Connect scanners and identity sources so the analysis sees your whole attack surface; mark business-critical assets as crown jewels."
            engines={["greenbone", "nuclei", "keycloak"]}
          />
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_360px]">
          <div className="min-w-0 space-y-2">
            {focus === "remediation" ? <div className="xl:hidden">{remediationCard}</div> : null}
            <div className="flex flex-wrap items-center gap-2 rounded border border-line bg-surface px-3 py-2 shadow-card">
              <label className="relative min-w-[220px] flex-1">
                <Search size={13} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-fg-subtle" aria-hidden />
                <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by asset, identity or target…" className="h-7 pl-7" aria-label="Filter attack paths" />
              </label>
              <label className="flex items-center gap-1.5 text-sm text-fg-muted">
                Min severity
                <Select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value as Severity)} className="h-7 w-28" aria-label="Minimum severity">
                  {Severity.options.map((s) => (
                    <option key={s} value={s}>
                      {humanize(s)}
                    </option>
                  ))}
                </Select>
              </label>
              <Checkbox label="Crown jewels only" checked={crownOnly} onChange={(e) => setCrownOnly(e.target.checked)} />
              {selectedFix ? (
                <button type="button" className="rounded-full border border-primary bg-primary-soft px-2 py-0.5 text-xs text-primary" onClick={() => setSelectedFix(null)}>
                  Paths broken by: {selectedFix.action} ✕
                </button>
              ) : null}
              <span className="ml-auto text-xs text-fg-muted">
                {formatInteger(filtered.length)} of {formatInteger(paths?.length ?? 0)} paths
              </span>
            </div>
            {filtered.length === 0 ? (
              <div className="rounded border border-line bg-surface shadow-card">
                <EmptyState compact title="No path matches these filters" />
              </div>
            ) : (
              filtered.slice(0, shown).map((p, i) => <AttackPathCard key={p.id} path={p} highlighted={Boolean(selectedFix)} defaultOpen={i === 0 && focus === "paths"} />)
            )}
            {filtered.length > shown ? (
              <button type="button" className="w-full rounded border border-line bg-surface py-2 text-sm text-primary hover:bg-surface-2" onClick={() => setShown((n) => n + PAGE)}>
                Show {Math.min(PAGE, filtered.length - shown)} more
              </button>
            ) : null}
          </div>
          <div className={focus === "remediation" ? "hidden xl:block" : ""}>
            <div className="xl:sticky xl:top-2">{remediationCard}</div>
          </div>
        </div>
      )}
    </div>
  );
}
