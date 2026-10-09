import { lazy, type ReactNode } from "react";
import { allNavPaths, AUX_PAGES, RAIL_MODULES, TOP_NAV } from "./navigation";
import { MODULE_ROUTES } from "./moduleRoutes";

export interface AppRoute {
  /** react-router path (supports params and trailing splats). */
  path: string;
  element: ReactNode;
}

const CommandCenterPage = lazy(() => import("../pages/command-center/CommandCenterPage"));
const MsspPage = lazy(() => import("../pages/MsspPage"));
const IncidentsPage = lazy(() => import("../pages/incidents/IncidentsPage"));
const IncidentDetailPage = lazy(() => import("../pages/incidents/IncidentDetailPage"));
const EscalationsPage = lazy(() => import("../pages/EscalationsPage"));
const OrganizationsPage = lazy(() => import("../pages/OrganizationsPage"));
const TrialManagerPage = lazy(() => import("../pages/TrialManagerPage"));
const PreferencesPage = lazy(() => import("../pages/PreferencesPage"));
const ReportsPage = lazy(() => import("../pages/reports/ReportsPage"));
const NotificationChannelsPage = lazy(() => import("../pages/automation/NotificationChannelsPage"));
const AutomationRulesPage = lazy(() => import("../pages/automation/AutomationRulesPage"));
export const ModulePlaceholderPage = lazy(() => import("../pages/ModulePlaceholderPage"));

/** Pages implemented in part A. */
export const CORE_ROUTES: AppRoute[] = [
  { path: "/", element: <CommandCenterPage /> },
  { path: "/mssp", element: <MsspPage /> },
  { path: "/incidents", element: <IncidentsPage /> },
  { path: "/incidents/:id", element: <IncidentDetailPage /> },
  { path: "/escalations", element: <EscalationsPage /> },
  { path: "/organizations", element: <OrganizationsPage /> },
  { path: "/trials", element: <TrialManagerPage /> },
  { path: "/preferences", element: <PreferencesPage /> },
  { path: "/reports", element: <ReportsPage /> },
  { path: "/soar/channels", element: <NotificationChannelsPage /> },
  { path: "/settings/notifications", element: <NotificationChannelsPage /> },
  { path: "/soar/automations", element: <AutomationRulesPage /> },
];

/**
 * Full authenticated route table: core pages + module pages + a placeholder for every
 * navigable path (and `<section>/*` detail paths) not yet implemented, so navigation never 404s.
 */
export function buildAppRoutes(moduleRoutes: AppRoute[] = MODULE_ROUTES): AppRoute[] {
  // Module routes win over core routes with the same path (part B may replace a core page).
  const byPath = new Map<string, AppRoute>();
  for (const r of CORE_ROUTES) byPath.set(r.path, r);
  for (const r of moduleRoutes) byPath.set(r.path, r);
  const explicit = [...byPath.values()];
  const covered = new Set(explicit.map((r) => r.path));
  // A real `<base>/*` route (a module workspace) also serves `<base>` and every sub-path; a
  // placeholder for those paths would out-rank it, so they count as covered.
  const splatBases = explicit.filter((r) => r.path.endsWith("/*")).map((r) => r.path.slice(0, -2));
  const servedBySplat = (path: string) => splatBases.some((b) => path === b || path.startsWith(`${b}/`));
  const placeholder = <ModulePlaceholderPage />;

  const placeholders: AppRoute[] = [];
  for (const path of allNavPaths()) {
    if (!covered.has(path) && !servedBySplat(path)) {
      placeholders.push({ path, element: placeholder });
      covered.add(path);
    }
  }
  const sections = new Set<string>([...RAIL_MODULES.map((m) => m.path), ...TOP_NAV.map((i) => i.path), ...AUX_PAGES.map((i) => i.path)]);
  for (const base of sections) {
    if (base === "/") continue;
    const splat = `${base}/*`;
    if (!covered.has(splat)) {
      placeholders.push({ path: splat, element: placeholder });
      covered.add(splat);
    }
  }
  return [...explicit, ...placeholders];
}
