import { useEffect, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { setMfaSetupHandler, setUnauthorizedHandler } from "../api/client";
import { queryKeys, useMe } from "../api/hooks";
import { SessionProvider } from "../app/session";
import { UiProvider } from "../app/ui";
import { LogoMark } from "../components/Logo";
import { ErrorState } from "../components/ErrorState";
import { MfaRequiredScreen } from "../features/mfa/MfaRequiredScreen";
import { AppShell } from "./AppShell";
import { StepUpDialog } from "./StepUpDialog";

/**
 * Registers the global 401 handler: drop every cached query (no tenant data outlives the
 * session) and route to /login, remembering where the user was.
 */
export function AuthRedirectBridge() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  useEffect(
    () =>
      setUnauthorizedHandler(() => {
        const { pathname, search } = window.location;
        if (pathname.startsWith("/login")) return;
        qc.clear();
        navigate(`/login?next=${encodeURIComponent(pathname + search)}`, { replace: true });
      }),
    [navigate, qc],
  );
  return null;
}

export function FullPageStatus({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-canvas p-6">
      <LogoMark size={40} />
      {children}
    </div>
  );
}

/** Session gate: resolves /auth/me, then mounts the tenancy context and the shell. */
export function AuthenticatedApp() {
  const me = useMe();
  const location = useLocation();
  const qc = useQueryClient();
  // The account may start requiring MFA mid-session: reload the profile to show the setup screen.
  useEffect(() => setMfaSetupHandler(() => void qc.invalidateQueries({ queryKey: queryKeys.me })), [qc]);

  if (me.isPending) {
    return (
      <FullPageStatus>
        <div role="status" className="text-sm text-fg-muted">
          Loading your Command Center…
        </div>
      </FullPageStatus>
    );
  }
  if (me.isError) {
    if (me.error.status === 401) {
      return <Navigate to={`/login?next=${encodeURIComponent(location.pathname + location.search)}`} replace />;
    }
    return (
      <FullPageStatus>
        <ErrorState error={me.error} onRetry={() => void me.refetch()} />
      </FullPageStatus>
    );
  }
  if (me.data.user?.mfaSetupRequired) {
    return <MfaRequiredScreen me={me.data} onDone={() => void me.refetch()} />;
  }
  return (
    <SessionProvider me={me.data}>
      <UiProvider>
        <AppShell />
        <StepUpDialog />
      </UiProvider>
    </SessionProvider>
  );
}
