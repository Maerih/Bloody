import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { lazy, Suspense, useMemo, useState, type ReactNode } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { isApiError } from "./api/client";
import { buildAppRoutes } from "./app/routes";
import { ThemeProvider } from "./app/theme";
import { AuthenticatedApp, AuthRedirectBridge, FullPageStatus } from "./layout/AuthenticatedApp";

const LoginPage = lazy(() => import("./pages/LoginPage"));
const NotFoundPage = lazy(() => import("./pages/NotFoundPage"));

/** Opt into React Router v7 behaviour now (transition-wrapped updates, splat-relative paths). */
export const ROUTER_FUTURE = { v7_startTransition: true, v7_relativeSplatPath: true } as const;

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        gcTime: 5 * 60_000,
        refetchOnWindowFocus: true,
        // Never retry client errors (401/403/404/422…); retry transient failures twice.
        retry: (failureCount, error) => !(isApiError(error) && error.status >= 400 && error.status < 500) && failureCount < 2,
      },
      mutations: { retry: false },
    },
  });
}

export function AppProviders({ children, queryClient }: { children: ReactNode; queryClient?: QueryClient }) {
  const [client] = useState(() => queryClient ?? createQueryClient());
  return (
    <QueryClientProvider client={client}>
      <ThemeProvider>{children}</ThemeProvider>
    </QueryClientProvider>
  );
}

/** Route table: public /login, everything else behind the session gate and app shell. */
export function AppRoutes() {
  const routes = useMemo(() => buildAppRoutes(), []);
  return (
    <>
      <AuthRedirectBridge />
      <Routes>
        <Route
          path="/login"
          element={
            <Suspense fallback={<FullPageStatus>{null}</FullPageStatus>}>
              <LoginPage />
            </Suspense>
          }
        />
        <Route element={<AuthenticatedApp />}>
          {routes.map((r) => (
            <Route key={r.path} path={r.path} element={r.element} />
          ))}
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </>
  );
}

export default function App() {
  return (
    <BrowserRouter future={ROUTER_FUTURE}>
      <AppProviders>
        <AppRoutes />
      </AppProviders>
    </BrowserRouter>
  );
}
