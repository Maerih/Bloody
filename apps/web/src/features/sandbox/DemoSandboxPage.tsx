import { FlaskConical, LogIn, LogOut, Map as MapIcon } from "lucide-react";
import { errorMessage } from "../../api/client";
import { useEnterSandbox, useExitSandbox, useSandbox } from "../../api/hooks";
import { Button, Card, PageHeader, SkeletonText } from "../../components";
import { useDocumentTitle } from "../../hooks/useDocumentTitle";
import { queueTour, useTour } from "./Tour";
import { TOUR_STEPS } from "./tourSteps";

/** /sandbox — explore the read-only demo account with a guided tour, like a first visit. */
export function DemoSandboxPage() {
  useDocumentTitle("Demo sandbox");
  const sandbox = useSandbox();
  const enter = useEnterSandbox();
  const exit = useExitSandbox();
  const tour = useTour();
  const s = sandbox.data;
  return (
    <div className="space-y-4">
      <PageHeader title="Demo Sandbox" subtitle="Explore a fully working SCIAT account with demo customers, incidents and endpoints — and a guided tour of every feature." />
      <Card title={<span className="inline-flex items-center gap-2"><FlaskConical className="h-4 w-4" aria-hidden /> {s?.inSandbox ? "You are exploring the sandbox" : "Try everything without touching your own data"}</span>}>
        {sandbox.isPending ? (
          <SkeletonText lines={3} />
        ) : (
          <div className="space-y-4 text-sm">
            <ul className="list-disc space-y-1 pl-5 text-fg-muted">
              <li>Demo MSSP customers with endpoints, identities, vulnerabilities and threat intel.</li>
              <li>Real incidents, escalations and attack paths produced by the detection, correlation and risk engines.</li>
              <li>Agents with isolation, App Control, managed antivirus, Microsoft 365 hardening, reports and automation.</li>
              <li>Read-only: look at anything, change nothing. Your own account is one click away.</li>
            </ul>
            <p className="text-fg-muted">The guided tour walks you through {TOUR_STEPS.length} stops, one feature at a time. Skip it whenever you like.</p>
            <div className="flex flex-wrap gap-2">
              {s?.inSandbox ? (
                <>
                  <Button variant="primary" icon={MapIcon} onClick={tour.start}>
                    Start the guided tour
                  </Button>
                  <Button icon={LogOut} loading={exit.isPending} onClick={() => exit.mutate(undefined, { onSuccess: (r) => (tour.stop(), window.location.assign(r.restored ? "/" : "/login")) })}>
                    Return to My Account
                  </Button>
                </>
              ) : s?.available ? (
                <>
                  <Button
                    variant="primary"
                    icon={LogIn}
                    loading={enter.isPending}
                    onClick={() =>
                      enter.mutate(undefined, {
                        onSuccess: () => {
                          queueTour();
                          window.location.assign("/");
                        },
                      })
                    }
                  >
                    Enter the Demo Sandbox
                  </Button>
                  <Button icon={MapIcon} onClick={tour.start}>
                    Tour my own account instead
                  </Button>
                </>
              ) : (
                <>
                  <Button variant="primary" icon={MapIcon} onClick={tour.start}>
                    Take the guided tour
                  </Button>
                  <p className="w-full text-fg-subtle">The demo account is not set up on this platform yet (operators: pnpm admin sandbox-setup --account &lt;slug&gt;). The tour runs in your own account meanwhile.</p>
                </>
              )}
            </div>
            {enter.error || exit.error ? <p role="alert" className="text-sev-critical">{errorMessage(enter.error ?? exit.error)}</p> : null}
          </div>
        )}
      </Card>
    </div>
  );
}
