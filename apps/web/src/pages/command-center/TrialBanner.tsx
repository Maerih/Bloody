import { MODULES } from "@bloody/contracts";
import { FlaskConical } from "lucide-react";
import { Link } from "react-router-dom";
import { useSession } from "../../app/session";
import { ButtonLink } from "../../components/Button";
import { daysUntil, formatDate } from "../../lib/format";

/** "Explore Your Bloody Trial" card — only rendered for accounts on the trial plan. */
export function TrialBanner() {
  const session = useSession();
  const trials = session.entitlements.filter((e) => e.state === "trial");
  return (
    <section className="mb-3 rounded border border-line bg-surface p-4 shadow-card" aria-labelledby="trial-banner-title">
      <h2 id="trial-banner-title" className="mb-3 text-base text-fg">
        Explore Your Bloody Trial
      </h2>
      <div className="grid gap-3 lg:grid-cols-[minmax(0,600px)_minmax(0,1fr)]">
        <div className="rounded border border-line p-4">
          <div className="text-2xs font-bold uppercase tracking-wide text-fg">Learn Bloody</div>
          <div className="mt-1 text-md text-fg">Explore the Demo Sandbox</div>
          <p className="mt-1 text-sm text-fg-muted">
            Perfect for learning about features and capabilities without installing anything — freely explore a fully configured Bloody account.
          </p>
          <ButtonLink to="/sandbox" variant="success" size="sm" icon={FlaskConical} className="mt-3">
            Launch Demo Sandbox
          </ButtonLink>
        </div>
        <div className="rounded border border-line p-4">
          <div className="text-2xs font-bold uppercase tracking-wide text-fg">Your trial</div>
          {trials.length === 0 ? (
            <p className="mt-1 text-sm text-fg-muted">No modules are currently in trial. Start one from the Trial Manager.</p>
          ) : (
            <ul className="mt-1 space-y-1">
              {trials.map((t) => {
                const name = MODULES.find((m) => m.key === t.module)?.name ?? t.module;
                const days = t.trialEndsAt ? daysUntil(t.trialEndsAt) : null;
                return (
                  <li key={t.module} className="flex items-center justify-between gap-3 text-sm">
                    <span className="truncate text-fg">{name}</span>
                    <span className={days !== null && days <= 3 ? "text-sev-critical" : "text-fg-muted"}>
                      {t.trialEndsAt ? `ends ${formatDate(t.trialEndsAt)}${days !== null && days >= 0 ? ` (${days} day${days === 1 ? "" : "s"})` : ""}` : "active"}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
          <Link to="/trials" className="mt-3 inline-block text-sm font-medium text-primary hover:underline">
            Open Trial Manager
          </Link>
        </div>
      </div>
    </section>
  );
}
