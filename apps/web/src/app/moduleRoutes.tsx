import { lazy, Suspense, type ComponentType, type LazyExoticComponent, type ReactNode } from "react";
import type { AppRoute } from "./routes";

/**
 * Module workspaces and part B pages. Workspaces register `<base>/*` so one element serves the
 * dashboard and every sub-page (the section comes from the URL); buildAppRoutes treats those
 * paths as covered. Aliases from the product spec (/vulnerabilities, /intel, /email, /deception,
 * /graph, /attack-paths, /automations, /settings/*) point at the same pages.
 */

const InvestigationsPage = lazy(() => import("../pages/investigations/InvestigationsPage"));
const InvestigationWorkspacePage = lazy(() => import("../pages/investigations/InvestigationWorkspacePage"));
const GraphExplorerPage = lazy(() => import("../pages/graph/GraphExplorerPage"));
const AttackPathsPage = lazy(() => import("../pages/attack-paths/AttackPathsPage"));
const AssetsPage = lazy(() => import("../pages/assets/AssetsPage"));
const AssetDetailPage = lazy(() => import("../pages/assets/AssetDetailPage"));
const AgentsPage = lazy(() => import("../pages/AgentsPage"));
const SearchPage = lazy(() => import("../pages/SearchPage"));

const EdrPage = lazy(() => import("../pages/modules/EdrPage"));
const ItdrPage = lazy(() => import("../pages/modules/ItdrPage"));
const NdrPage = lazy(() => import("../pages/modules/NdrPage"));
const SiemPage = lazy(() => import("../pages/modules/SiemPage"));
const XdrPage = lazy(() => import("../pages/modules/XdrPage"));
const AsmPage = lazy(() => import("../pages/modules/AsmPage"));
const EspmPage = lazy(() => import("../pages/modules/EspmPage"));
const IspmPage = lazy(() => import("../pages/modules/IspmPage"));
const CspmPage = lazy(() => import("../pages/modules/CspmPage"));
const CiemPage = lazy(() => import("../pages/modules/CiemPage"));
const SspmPage = lazy(() => import("../pages/modules/SspmPage"));
const VmPage = lazy(() => import("../pages/modules/VmPage"));
const K8sPage = lazy(() => import("../pages/modules/K8sPage"));
const CtiPage = lazy(() => import("../pages/modules/CtiPage"));
const DfirPage = lazy(() => import("../pages/modules/DfirPage"));
const SoarPage = lazy(() => import("../pages/modules/SoarPage"));
const EmailPage = lazy(() => import("../pages/modules/EmailPage"));
const DeceptionPage = lazy(() => import("../pages/modules/DeceptionPage"));

const AiSocPage = lazy(() => import("../pages/ai/AiSocPage"));
const AiSettingsPage = lazy(() => import("../pages/ai/AiSettingsPage"));
const IntegrationsHubPage = lazy(() => import("../pages/integrations/IntegrationsHubPage"));
const AutomationsPage = lazy(() => import("../pages/automation/AutomationsPage"));
const NotificationChannelsPage = lazy(() => import("../pages/automation/NotificationChannelsPage"));

const SettingsLayout = lazy(() => import("../pages/settings/SettingsLayout").then((m) => ({ default: m.SettingsLayout })));
const SettingsOverviewPage = lazy(() => import("../pages/settings/SettingsOverviewPage"));
const UsersPage = lazy(() => import("../pages/settings/UsersPage"));
const ApiCredentialsPage = lazy(() => import("../pages/settings/ApiCredentialsPage"));
const BillingPage = lazy(() => import("../pages/settings/BillingPage"));
const AuditLogPage = lazy(() => import("../pages/settings/AuditLogPage"));
const DataArchivePage = lazy(() => import("../pages/settings/DataArchivePage"));
const PreferencesPage = lazy(() => import("../pages/PreferencesPage"));

/** Wrap a settings section page in the settings frame (section nav + page). */
function settings(Page: LazyExoticComponent<ComponentType>): ReactNode {
  return (
    <Suspense fallback={null}>
      <SettingsLayout>
        <Page />
      </SettingsLayout>
    </Suspense>
  );
}

/** `<base>` and `<base>/*` → one workspace element. */
function workspace(base: string, element: ReactNode): AppRoute[] {
  return [{ path: `${base}/*`, element }];
}

export const MODULE_ROUTES: AppRoute[] = [
  // Investigations & pivots
  { path: "/investigations", element: <InvestigationsPage /> },
  { path: "/investigations/:id", element: <InvestigationWorkspacePage /> },
  { path: "/graph", element: <GraphExplorerPage /> },
  { path: "/xdr/graph", element: <GraphExplorerPage /> },
  { path: "/attack-paths", element: <AttackPathsPage /> },
  { path: "/assets", element: <AssetsPage /> },
  { path: "/assets/:id", element: <AssetDetailPage /> },
  { path: "/agents", element: <AgentsPage /> },
  { path: "/search", element: <SearchPage /> },

  // Module workspaces (lenses over the same data model)
  ...workspace("/edr", <EdrPage />),
  ...workspace("/itdr", <ItdrPage />),
  ...workspace("/ndr", <NdrPage />),
  ...workspace("/siem", <SiemPage />),
  ...workspace("/xdr", <XdrPage />),
  ...workspace("/asm", <AsmPage />),
  ...workspace("/espm", <EspmPage />),
  ...workspace("/ispm", <IspmPage />),
  ...workspace("/cspm", <CspmPage />),
  ...workspace("/ciem", <CiemPage />),
  ...workspace("/sspm", <SspmPage />),
  ...workspace("/vm", <VmPage />),
  ...workspace("/vulnerabilities", <VmPage />),
  ...workspace("/k8s", <K8sPage />),
  ...workspace("/cti", <CtiPage />),
  ...workspace("/intel", <CtiPage />),
  ...workspace("/dfir", <DfirPage />),
  ...workspace("/soar", <SoarPage />),
  // Part A registered these as standalone pages; inside the SOAR workspace they keep the tabs.
  { path: "/soar/automations", element: <SoarPage /> },
  { path: "/soar/channels", element: <SoarPage /> },
  ...workspace("/mail", <EmailPage />),
  ...workspace("/email", <EmailPage />),
  ...workspace("/decoy", <DeceptionPage />),
  ...workspace("/deception", <DeceptionPage />),

  // AI SOC
  { path: "/ai", element: <AiSocPage /> },
  { path: "/ai/conversations", element: <AiSocPage /> },
  { path: "/ai/actions", element: <AiSocPage /> },
  { path: "/ai/providers", element: <AiSettingsPage /> },
  { path: "/ai/policies", element: <AiSettingsPage /> },

  // Integrations Hub
  ...workspace("/hub", <IntegrationsHubPage />),
  { path: "/integrations", element: <IntegrationsHubPage /> },

  // Automations
  { path: "/automations", element: <AutomationsPage /> },

  // Settings (section nav + page)
  { path: "/settings", element: settings(SettingsOverviewPage) },
  { path: "/settings/users", element: settings(UsersPage) },
  { path: "/users", element: settings(UsersPage) },
  { path: "/settings/api-credentials", element: settings(ApiCredentialsPage) },
  { path: "/settings/ai", element: settings(AiSettingsPage) },
  { path: "/settings/ai/policies", element: settings(AiSettingsPage) },
  { path: "/settings/notifications", element: settings(NotificationChannelsPage) },
  { path: "/settings/billing", element: settings(BillingPage) },
  { path: "/billing", element: settings(BillingPage) },
  { path: "/settings/audit", element: settings(AuditLogPage) },
  { path: "/audit", element: settings(AuditLogPage) },
  { path: "/settings/preferences", element: settings(PreferencesPage) },
  { path: "/preferences", element: settings(PreferencesPage) },
  { path: "/settings/data-archive", element: settings(DataArchivePage) },
];
