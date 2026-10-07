import type { AppRoute } from "./routes";

/**
 * Module pages registered by part B (EDR, ITDR, NDR, SIEM, …, Reports, Users, Integrations,
 * AI SOC, Settings…). Any nav path listed in app/navigation.ts that has no route here or in
 * CORE_ROUTES automatically renders the generic ModulePlaceholderPage, so adding a page is:
 *
 *   const ReportsPage = lazy(() => import("../pages/reports/ReportsPage"));
 *   export const MODULE_ROUTES: AppRoute[] = [{ path: "/reports", element: <ReportsPage /> }];
 */
export const MODULE_ROUTES: AppRoute[] = [];
