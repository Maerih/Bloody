import { DashboardRole } from "@bloody/contracts";
import { clsx } from "clsx";
import { Building2, RefreshCw } from "lucide-react";
import { useCommandCenterSummary } from "../../api/hooks";
import { DASHBOARD_PRESETS, DASHBOARD_ROLES } from "../../app/dashboardPresets";
import { useSession } from "../../app/session";
import { ButtonLink, IconButton } from "../../components/Button";
import { ErrorState } from "../../components/ErrorState";
import { Select } from "../../components/Form";
import { PageHeader } from "../../components/PageHeader";
import { RelativeTime } from "../../components/RelativeTime";
import { ReportMenu } from "../../components/ReportMenu";
import { CardSkeleton } from "../../components/Skeleton";
import { isNumber, useLocalStorageState } from "../../lib/storage";
import { TrialBanner } from "./TrialBanner";
import { TriageFeed } from "./TriageFeed";
import { SPAN_CLASSES, WIDGETS } from "./widgets";

export const WINDOW_OPTIONS = [7, 30, 90] as const;
const isWindow = (v: unknown): v is number => isNumber(v) && (WINDOW_OPTIONS as readonly number[]).includes(v);

/**
 * Command Center (/) — one round-trip (`/command-center/summary`) renders a role-aware set of
 * widgets for the selected organization (or all organizations). Nothing is fabricated: loading
 * shows skeletons, failures show the API error, zero data shows real empty states.
 */
export default function CommandCenterPage() {
  const session = useSession();
  const [windowDays, setWindowDays] = useLocalStorageState<number>("commandCenter.windowDays", 90, isWindow);
  const summary = useCommandCenterSummary(windowDays);
  const preset = DASHBOARD_PRESETS[session.dashboardRole];
  const showMsspLink = session.isMssp && session.canSelectAll;

  return (
    <div>
      <PageHeader
        title="Command Center"
        subtitle={
          <span className="text-sm">
            {session.organization ? session.organization.name : session.canSelectAll ? "All organizations" : session.account.name}
            {summary.data ? (
              <>
                {" · updated "}
                <RelativeTime value={summary.data.generatedAt} />
              </>
            ) : null}
          </span>
        }
        actions={
          <>
            <label className="flex items-center gap-1.5 text-sm text-fg-muted">
              View
              <Select
                value={session.dashboardRole}
                onChange={(e) => session.setDashboardRole(DashboardRole.parse(e.target.value))}
                className="h-7 w-48"
                aria-label="Dashboard view"
                title={preset.description}
              >
                {DASHBOARD_ROLES.map((r) => (
                  <option key={r} value={r}>
                    {DASHBOARD_PRESETS[r].label}
                  </option>
                ))}
              </Select>
            </label>
            <Select value={windowDays} onChange={(e) => setWindowDays(Number(e.target.value))} className="h-7 w-32" aria-label="Time window">
              {WINDOW_OPTIONS.map((d) => (
                <option key={d} value={d}>
                  Last {d} days
                </option>
              ))}
            </Select>
            <IconButton icon={RefreshCw} label="Refresh" onClick={() => void summary.refetch()} className={clsx(summary.isFetching && "[&>svg]:animate-spin")} />
            <ReportMenu reports={preset.reports} defaultReport={preset.defaultReport} periodDays={windowDays} />
            {showMsspLink ? (
              <ButtonLink to="/mssp" size="sm" icon={Building2}>
                MSSP view
              </ButtonLink>
            ) : null}
          </>
        }
      />

      {session.plan === "trial" ? <TrialBanner /> : null}

      <div className={clsx("grid grid-cols-1 gap-3", preset.showTriage && "xl:grid-cols-[minmax(0,1fr)_minmax(300px,30%)]")}>
        <div className="grid min-w-0 auto-rows-min grid-cols-6 gap-3 [grid-auto-flow:row_dense]" data-testid="command-center-widgets">
          {summary.isPending ? (
            <>
              <CardSkeleton className="col-span-6" rows={1} />
              <CardSkeleton className="col-span-6 2xl:col-span-3" rows={4} />
              <CardSkeleton className="col-span-6 2xl:col-span-3" rows={4} />
              <CardSkeleton className="col-span-6 md:col-span-3 2xl:col-span-2" rows={4} />
              <CardSkeleton className="col-span-6 md:col-span-3 2xl:col-span-2" rows={4} />
              <CardSkeleton className="col-span-6 md:col-span-3 2xl:col-span-2" rows={4} />
            </>
          ) : summary.isError ? (
            <div className="col-span-6 rounded border border-line bg-surface shadow-card">
              <ErrorState error={summary.error} onRetry={() => void summary.refetch()} />
            </div>
          ) : (
            preset.widgets.map((key) => {
              const def = WIDGETS[key];
              const Component = def.Component;
              return (
                <div key={key} className={clsx(SPAN_CLASSES[def.span], "min-w-0")} data-widget={key}>
                  <Component summary={summary.data} windowDays={windowDays} />
                </div>
              );
            })
          )}
        </div>
        {preset.showTriage ? (
          <aside className="min-w-0 xl:sticky xl:top-[56px] xl:h-[calc(100vh-72px)]" aria-label="Triage feed">
            <TriageFeed items={summary.data?.triage} loading={summary.isPending} showOrganization={session.organizationId === null} />
          </aside>
        ) : null}
      </div>
    </div>
  );
}
