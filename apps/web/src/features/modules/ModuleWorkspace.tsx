import type { ModuleKey } from "@bloody/contracts";
import { Lock } from "lucide-react";
import type { ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { RAIL_MODULES, type RailModule } from "../../app/navigation";
import { ORG_PARAM, useSession } from "../../app/session";
import { StatusBadge } from "../../components/Badge";
import { ButtonLink } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { PageHeader } from "../../components/PageHeader";
import { Tabs } from "../../components/Tabs";
import { railItemsFor } from "../../layout/LeftRail";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";

/** Locked / trial-ended state for a module the tenant is not entitled to. */
export function ModuleLockedState({ module, name, accountName }: { module: ModuleKey; name: string; accountName: string }) {
  const session = useSession();
  const state = session.moduleState(module);
  return (
    <EmptyState
      icon={Lock}
      tone="locked"
      title={`${name} is not enabled for ${accountName}`}
      description={
        state === "trial_ended"
          ? "Your trial has ended. Subscribe to keep using this module."
          : state === "available"
            ? "Start a free trial to explore this module with your own data."
            : "This module is not included in your current plan."
      }
      action={
        <ButtonLink to={`/trials?module=${module}`} variant="primary" size="sm">
          {state === "available" ? "Start trial" : "View plans & trials"}
        </ButtonLink>
      }
    />
  );
}

export type SectionRenderer = () => ReactNode;

export interface ModuleWorkspaceProps {
  /** RAIL_MODULES[].id */
  moduleId: string;
  /** Section key ("" = dashboard, "processes" for /edr/processes…) → renderer. */
  sections: Record<string, SectionRenderer>;
  /** Force a section (alias routes such as /vulnerabilities). */
  section?: string;
  /**
   * Alias entry points: alias base path → section it opens (e.g. `{"/intel": ""}` makes
   * /intel/indicators open the "indicators" section of /cti). Tabs still link to canonical paths.
   */
  aliases?: Record<string, string>;
  actions?: ReactNode;
}

/** Keep the organization scope (?org=) when moving between module sections. */
export function withOrg(pathname: string, search: string): { pathname: string; search: string } {
  const org = new URLSearchParams(search).get(ORG_PARAM);
  return { pathname, search: org ? `?${ORG_PARAM}=${encodeURIComponent(org)}` : "" };
}

export function sectionFromPath(module: Pick<RailModule, "path">, pathname: string, aliases: Record<string, string> = {}): string {
  const path = pathname.length > 1 && pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
  if (path === module.path) return "";
  if (path.startsWith(`${module.path}/`)) return path.slice(module.path.length + 1).split("/")[0] ?? "";
  for (const [base, section] of Object.entries(aliases)) {
    if (path === base) return section;
    if (path.startsWith(`${base}/`)) return path.slice(base.length + 1).split("/")[0] ?? section;
  }
  return "";
}

/**
 * Module workspace frame: one header + sub-page tabs for every module, entitlement gate, and
 * the section's content. Module pages are lenses over the same data model — sections compose
 * the shared tables, drawers and graph rather than bespoke dashboards.
 */
export function ModuleWorkspace({ moduleId, sections, section, aliases, actions }: ModuleWorkspaceProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const session = useSession();
  const module = RAIL_MODULES.find((m) => m.id === moduleId);
  if (!module) throw new Error(`Unknown module ${moduleId}`);
  const key = section ?? sectionFromPath(module, location.pathname, aliases);
  const item = module.items.find((i) => i.path === (key ? `${module.path}/${key}` : module.path)) ?? module.items[0];
  const enabled = !module.module || session.isModuleEnabled(module.module);
  const subItems = railItemsFor(module, session);
  const render = sections[key];
  const title = item && item.path !== module.path ? item.label : module.name;

  return (
    <div>
      <PageHeader
        title={title}
        subtitle={item?.description ?? module.description}
        breadcrumbs={item && item.path !== module.path ? [{ label: module.name, href: module.path }, { label: item.label }] : undefined}
        actions={
          <>
            {actions}
            {module.module && session.moduleState(module.module) === "trial" ? <StatusBadge status="trial" /> : null}
          </>
        }
      >
        {enabled && subItems.length > 1 ? (
          <Tabs ariaLabel={`${module.name} sections`} value={item?.path ?? module.path} onChange={(path) => navigate(withOrg(path, location.search))} tabs={subItems.map((s) => ({ id: s.path, label: s.label, icon: s.icon }))} />
        ) : null}
      </PageHeader>
      {!enabled && module.module ? (
        <div className="rounded border border-line bg-surface shadow-card">
          <ModuleLockedState module={module.module} name={module.name} accountName={session.account.name} />
        </div>
      ) : render ? (
        render()
      ) : (
        <div className="rounded border border-line bg-surface shadow-card">
          <ConnectEngineEmptyState title={`No ${title.toLowerCase()} data yet`} module={module.module ?? undefined} description="This view fills in as connected integrations report for the selected organization." />
        </div>
      )}
    </div>
  );
}

/** Responsive KPI row. */
export function KpiGrid({ children }: { children: ReactNode }) {
  return <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">{children}</div>;
}
