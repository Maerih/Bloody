import { FlaskConical, LogOut, Map as MapIcon } from "lucide-react";
import { useExitSandbox } from "../../api/hooks";
import { useSession } from "../../app/session";
import { errorMessage } from "../../api/client";
import { useTour } from "./Tour";

/** "Currently exploring the SCIAT Demo Sandbox · Return to My Account" — on every page while in the sandbox. */
export function SandboxBanner() {
  const session = useSession();
  const exit = useExitSandbox();
  const tour = useTour();
  if (session.me.session?.method !== "sandbox") return null;
  return (
    <div role="region" aria-label="Demo sandbox" className="sticky top-11 z-30 flex flex-wrap items-center justify-center gap-x-4 gap-y-1 bg-brand px-4 py-1.5 text-sm text-white">
      <span className="inline-flex items-center gap-2">
        <FlaskConical className="h-4 w-4" aria-hidden />
        Currently exploring the <span className="font-semibold">SCIAT Demo Sandbox</span> — read-only, nothing here can be changed.
      </span>
      {!tour.active ? (
        <button type="button" className="inline-flex items-center gap-1 underline-offset-2 hover:underline" onClick={tour.start}>
          <MapIcon className="h-4 w-4" aria-hidden /> Take the tour
        </button>
      ) : null}
      <button
        type="button"
        className="inline-flex items-center gap-1 rounded bg-white/15 px-2 py-0.5 font-medium hover:bg-white/25 disabled:opacity-60"
        disabled={exit.isPending}
        onClick={() =>
          exit.mutate(undefined, {
            onSuccess: (r) => {
              tour.stop();
              window.location.assign(r.restored ? "/" : "/login");
            },
          })
        }
      >
        <LogOut className="h-4 w-4" aria-hidden /> Return to My Account
      </button>
      {exit.error ? <span role="alert">{errorMessage(exit.error)}</span> : null}
    </div>
  );
}
