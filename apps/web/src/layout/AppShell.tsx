import { Suspense, useEffect } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { ErrorBoundary } from "../components/ErrorBoundary";
import { CardSkeleton, Skeleton } from "../components/Skeleton";
import { CommandPalette } from "./CommandPalette";
import { GlobalShortcuts } from "./GlobalShortcuts";
import { HelpPill } from "./HelpPill";
import { LeftRail } from "./LeftRail";
import { ShortcutHelpDialog } from "./ShortcutHelpDialog";
import { TopBar } from "./TopBar";
import { SandboxBanner } from "../features/sandbox/SandboxBanner";
import { TourProvider } from "../features/sandbox/Tour";

export function PageSkeleton() {
  return (
    <div className="space-y-4" role="status" aria-label="Loading page">
      <Skeleton className="h-7 w-64" />
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <CardSkeleton />
        <CardSkeleton />
        <CardSkeleton />
      </div>
      <CardSkeleton rows={6} />
    </div>
  );
}

/** Paper is white: print in the light theme, then switch back. */
function usePrintInLightTheme() {
  useEffect(() => {
    const root = document.documentElement;
    let wasDark = false;
    const before = () => {
      wasDark = root.classList.contains("dark");
      if (wasDark) root.classList.remove("dark");
    };
    const after = () => {
      if (wasDark) root.classList.add("dark");
    };
    window.addEventListener("beforeprint", before);
    window.addEventListener("afterprint", after);
    return () => {
      window.removeEventListener("beforeprint", before);
      window.removeEventListener("afterprint", after);
    };
  }, []);
}

/** Authenticated application frame: top bar, left rail, content outlet and global overlays. */
export function AppShell() {
  const location = useLocation();
  usePrintInLightTheme();
  return (
    <TourProvider>
    <div className="min-h-screen bg-canvas">
      <a href="#main" className="sr-only z-[100] rounded bg-primary px-3 py-2 text-white focus:not-sr-only focus:fixed focus:left-2 focus:top-2">
        Skip to content
      </a>
      <TopBar />
      <LeftRail />
      <main id="main" tabIndex={-1} className="min-h-screen pl-[60px] pt-11 focus:outline-none print:min-h-0 print:p-0">
        <SandboxBanner />
        <div className="mx-auto max-w-[1920px] px-4 pb-16 pt-4 lg:px-6 print:max-w-none print:p-0">
          <ErrorBoundary resetKey={location.pathname}>
            <Suspense fallback={<PageSkeleton />}>
              <Outlet />
            </Suspense>
          </ErrorBoundary>
        </div>
      </main>
      <HelpPill />
      <CommandPalette />
      <ShortcutHelpDialog />
      <GlobalShortcuts />
    </div>
    </TourProvider>
  );
}
