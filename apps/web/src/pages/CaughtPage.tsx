import { GraduationCap, ShieldAlert, TriangleAlert } from "lucide-react";
import { useEffect } from "react";
import { useParams } from "react-router-dom";
import { isApiError } from "../api/client";
import { useRevealPhish } from "../api/hooks";
import { LogoMark } from "../components/Logo";

/**
 * Opened from a simulated phishing email. Loading this page (not fetching the link) records the
 * click, then explains what the person should have noticed. It never asks for anything.
 */
export default function CaughtPage() {
  const { token = "" } = useParams();
  const reveal = useRevealPhish();
  const { mutate } = reveal;
  useEffect(() => {
    mutate(token);
  }, [token, mutate]);
  const r = reveal.data;

  return (
    <div className="min-h-screen bg-canvas text-fg">
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex max-w-2xl items-center justify-between px-4 py-3">
          <span className="inline-flex items-center gap-2 text-lg font-semibold text-heading">
            <LogoMark /> SCIAT
          </span>
          <span className="text-sm text-fg-muted">Security awareness</span>
        </div>
      </header>
      <main className="mx-auto max-w-2xl space-y-5 px-4 py-8">
        {reveal.isError ? (
          <>
            <h1 className="text-xl font-semibold text-heading">This link is no longer active</h1>
            <p className="text-fg-muted">{isApiError(reveal.error) && reveal.error.status === 404 ? "It belonged to a security awareness exercise. Nothing else is needed from you." : "Please try again in a moment."}</p>
          </>
        ) : !r ? (
          <p>One moment…</p>
        ) : (
          <>
            <div className="flex items-start gap-3 rounded-md border border-sev-medium/40 bg-sev-medium/10 p-4">
              <ShieldAlert className="mt-0.5 h-6 w-6 shrink-0 text-sev-medium" aria-hidden />
              <div>
                <h1 className="text-xl font-semibold text-heading">This was a phishing simulation</h1>
                <p className="mt-1">
                  Hi {r.learner.name}, the email “{r.email.subject}” from “{r.email.fromName}” was a safe test run for {r.organization.name}. Nothing was collected and you are not in trouble: this is exactly how we all learn to spot the real thing.
                </p>
              </div>
            </div>
            <section>
              <h2 className="mb-2 font-semibold text-heading">What could have given it away</h2>
              <ul className="space-y-2">
                {r.redFlags.map((f) => (
                  <li key={f} className="flex gap-2">
                    <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-sev-high" aria-hidden />
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
            </section>
            <section className="rounded-md border border-line bg-surface p-4">
              <h2 className="font-semibold text-heading">Next time</h2>
              <p className="mt-1 text-fg-muted">Do not click links in unexpected messages. Open the service yourself, and report suspicious emails to your IT or security team.</p>
              {r.trainingUrl && r.lesson ? (
                <a className="mt-3 inline-flex items-center gap-2 rounded bg-brand px-3 py-2 text-sm font-medium text-white hover:opacity-90" href={r.trainingUrl}>
                  <GraduationCap className="h-4 w-4" aria-hidden /> Take the {r.lesson.minutes}-minute lesson: {r.lesson.title}
                </a>
              ) : null}
            </section>
          </>
        )}
      </main>
    </div>
  );
}
