import { MODULES, type ModuleKey, type ModuleState } from "@bloody/contracts";
import { clsx } from "clsx";
import { CirclePlay, Copy, Mail } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { errorMessage } from "../api/client";
import { useEntitlements, useStartTrial } from "../api/hooks";
import type { EntitlementView } from "../api/types";
import { APP_CONFIG, isExternalUrl } from "../app/config";
import { RAIL_MODULES } from "../app/navigation";
import { useSession } from "../app/session";
import { Badge } from "../components/Badge";
import { Button, ButtonLink } from "../components/Button";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { daysUntil, formatDate } from "../lib/format";

/** Product copy for each module card (marketing text, not customer data). */
const MODULE_COPY: Partial<Record<ModuleKey, { tagline: string; body: string }>> = {
  edr: { tagline: "Protect your endpoints", body: "Confirmed threats with actionable remediations for your endpoints, powered by our Security Operations Center." },
  xdr: { tagline: "Correlate every signal", body: "Cross-domain detection that stitches endpoint, identity, network and cloud signals into single incidents." },
  itdr: { tagline: "Secure your identities", body: "Continue securing cloud identity accounts in your environment from takeover, token theft and MFA abuse." },
  ndr: { tagline: "See your network", body: "Flow, DNS and TLS analytics that surface beaconing, lateral movement and exfiltration." },
  siem: { tagline: "Keep every log", body: "Subscribe to keep collecting, searching and correlating logs and events from your environment." },
  asm: { tagline: "Know your perimeter", body: "Continuous discovery of domains, certificates and exposed services — including the ones you forgot." },
  espm: { tagline: "Fix what matters first", body: "Exposure prioritized by exploitable attack paths to your crown jewels, not by raw counts." },
  ispm: { tagline: "Reduce identity risk", body: "Privilege analysis, MFA coverage and dormant or risky service accounts in one place." },
  cspm: { tagline: "Harden your cloud", body: "Misconfigurations, public exposure and compliance benchmarks across AWS, Azure and GCP." },
  ciem: { tagline: "Right-size cloud access", body: "Find excessive permissions and risky cross-account trust in cloud IAM." },
  sspm: { tagline: "Secure your SaaS", body: "Configuration drift, risky third-party apps and oversharing across your SaaS estate." },
  vuln: { tagline: "Patch by real risk", body: "Risk-based vulnerability management with CVSS, EPSS, known-exploited intelligence and SLA tracking." },
  container: { tagline: "Protect workloads", body: "Image vulnerabilities, Kubernetes posture and runtime detection for containers." },
  cti: { tagline: "Know your adversary", body: "Threat intelligence matched against your telemetry, identities and attack surface." },
  dfir: { tagline: "Investigate with evidence", body: "Cases, evidence with chain of custody, timelines and remote forensic collection." },
  soar: { tagline: "Respond at machine speed", body: "Playbooks, approvals and automated notifications — with humans in the loop for risky actions." },
  email: { tagline: "Stop phishing", body: "Detect phishing, impersonation and malicious attachments before users click." },
  deception: { tagline: "Catch intruders early", body: "Decoys, canaries and honeytokens that raise high-fidelity alerts on first touch." },
  ai_soc: { tagline: "Your AI analyst", body: "AI that investigates, explains and recommends within the tool permissions you configure." },
};

function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]!.toUpperCase())
    .join("");
}

function ContactSalesButton({ size = "md" }: { size?: "sm" | "md" | "lg" }) {
  const url = APP_CONFIG.salesContactUrl;
  if (!url) return null;
  return (
    <ButtonLink to={url} external={isExternalUrl(url)} variant="primary" size={size} icon={Mail}>
      Contact Sales
    </ButtonLink>
  );
}

/** Trial Manager (/trials): account team + every module with its subscription/trial state. */
export default function TrialManagerPage() {
  useDocumentTitle("Trial Manager");
  const session = useSession();
  const [params] = useSearchParams();
  const focus = params.get("module");
  const entitlements = useEntitlements();
  const startTrial = useStartTrial();
  const canManage = session.can("billing:write", null) || session.can("settings:write", null);
  const [copied, setCopied] = useState(false);

  const byModule = useMemo(() => {
    const map = new Map<ModuleKey, EntitlementView>();
    for (const e of session.entitlements) map.set(e.module, e);
    for (const e of entitlements.data ?? []) map.set(e.module, e);
    return map;
  }, [entitlements.data, session.entitlements]);

  useEffect(() => {
    if (!focus) return;
    document.getElementById(`module-${focus}`)?.scrollIntoView?.({ behavior: "smooth", block: "center" });
  }, [focus]);

  const team = session.me.accountTeam?.[0] ?? null;
  const modules = MODULES.filter((m) => m.key !== "command_center");

  return (
    <div className="mx-auto max-w-6xl py-4">
      <h1 className="font-display text-3xl font-bold text-fg">Trial Manager</h1>
      <p className="mt-1 text-xl text-fg">Start your trial with any combination of products, you can try the rest later.</p>

      <section id="contact" className="mt-8 flex items-center gap-4" aria-label="Account team">
        <span className="inline-flex h-16 w-16 shrink-0 items-center justify-center rounded-full bg-healthy text-xl font-bold text-white">
          {team ? initials(team.name) : "B"}
        </span>
        <div className="min-w-0">
          <div className="text-sm font-bold uppercase tracking-wide text-fg">Account team</div>
          {team ? (
            <>
              <div className="text-xl font-semibold text-fg">{team.name}</div>
              <p className="text-md text-fg">
                Here to help with demos, pricing, and how to make the most of your trial.{" "}
                <a href={`mailto:${team.email}`} className="font-semibold text-healthy underline">
                  {team.email}
                </a>
                <button
                  type="button"
                  className="ml-1 inline-flex align-middle text-healthy"
                  aria-label="Copy email address"
                  onClick={() => {
                    void navigator.clipboard?.writeText(team.email).then(() => setCopied(true));
                  }}
                >
                  <Copy size={14} aria-hidden />
                </button>
                {copied ? <span className="ml-1 text-xs text-fg-muted">Copied</span> : null}
              </p>
            </>
          ) : (
            <>
              <div className="text-xl font-semibold text-fg">Bloody sales team</div>
              <p className="text-md text-fg-muted">Talk to us about demos, pricing and how to make the most of your trial.</p>
              <div className="mt-2">
                <ContactSalesButton size="sm" />
              </div>
            </>
          )}
        </div>
      </section>

      {startTrial.isError ? (
        <p role="alert" className="mt-4 text-sm text-sev-critical">
          {errorMessage(startTrial.error)}
        </p>
      ) : null}

      <div className="mt-8 grid grid-cols-1 gap-5 lg:grid-cols-2">
        {modules.map((m) => {
          const ent = byModule.get(m.key) ?? null;
          const state: ModuleState = ent?.state ?? session.moduleState(m.key);
          const copy = MODULE_COPY[m.key];
          const rail = RAIL_MODULES.find((r) => r.module === m.key);
          return (
            <article
              key={m.key}
              id={`module-${m.key}`}
              className={clsx("flex flex-col rounded border bg-surface p-5 shadow-card", focus === m.key ? "border-primary ring-2 ring-primary/30" : "border-line")}
              aria-labelledby={`module-title-${m.key}`}
            >
              <div className="flex items-start justify-between gap-3">
                <h2 id={`module-title-${m.key}`} className="max-w-[18rem] text-xl font-bold leading-snug text-fg">
                  {m.name}
                </h2>
                {rail ? <rail.icon size={26} strokeWidth={1.4} aria-hidden className="shrink-0 text-fg-subtle" /> : null}
              </div>
              {copy ? <p className="mt-1 text-md text-fg-subtle">{copy.tagline}</p> : null}
              <ModuleStateLine state={state} entitlement={ent} />
              {copy ? <p className="mt-2 text-md text-fg">{copy.body}</p> : null}
              <div className="mt-auto pt-5">
                <ModuleAction
                  module={m.key}
                  state={state}
                  canManage={canManage}
                  pending={startTrial.isPending && startTrial.variables === m.key}
                  onStart={() => startTrial.mutate(m.key)}
                  openPath={rail?.path ?? "/"}
                />
                {state === "trial_ended" ? <UninstallNote entitlement={ent} /> : null}
              </div>
            </article>
          );
        })}
      </div>
    </div>
  );
}

function ModuleStateLine({ state, entitlement }: { state: ModuleState; entitlement: EntitlementView | null }) {
  if (state === "trial") {
    const days = entitlement?.trialEndsAt ? daysUntil(entitlement.trialEndsAt) : null;
    return (
      <p className="mt-2 text-md text-primary">
        Trial active{entitlement?.trialEndsAt ? ` · ends ${formatDate(entitlement.trialEndsAt)}` : ""}
        {days !== null && days >= 0 ? ` (in ${days} day${days === 1 ? "" : "s"})` : ""}
      </p>
    );
  }
  if (state === "trial_ended") return <p className="mt-2 text-md text-fg-subtle">Trial Ended</p>;
  if (state === "locked") return <p className="mt-2 text-md text-fg-subtle">Not included in your plan</p>;
  return null;
}

function ModuleAction({ module, state, canManage, pending, onStart, openPath }: { module: ModuleKey; state: ModuleState; canManage: boolean; pending: boolean; onStart: () => void; openPath: string }) {
  if (state === "active") {
    return (
      <div className="flex items-center justify-between">
        <span className="text-md font-bold text-healthy">Subscription Active</span>
        <ButtonLink to={openPath} size="sm">
          Open
        </ButtonLink>
      </div>
    );
  }
  if (state === "trial") {
    return (
      <div className="flex flex-wrap items-center gap-2">
        <ButtonLink to={openPath} size="md" variant="secondary">
          Open
        </ButtonLink>
        <ContactSalesButton />
      </div>
    );
  }
  if (state === "available") {
    return canManage ? (
      <Button variant="primary" size="lg" icon={CirclePlay} loading={pending} onClick={onStart} aria-label={`Start trial of ${module}`}>
        Start Trial
      </Button>
    ) : (
      <p className="text-sm text-fg-muted">Ask an account administrator to start this trial.</p>
    );
  }
  return (
    <div className="flex flex-wrap items-center gap-2">
      <ContactSalesButton />
      {!APP_CONFIG.salesContactUrl ? <Badge tone="outline">Contact your Bloody representative</Badge> : null}
    </div>
  );
}

function UninstallNote({ entitlement }: { entitlement: EntitlementView | null }) {
  if (!entitlement?.uninstallAt) {
    return <p className="mt-3 text-sm text-fg-subtle">Agents and integrations for this module are scheduled for automatic removal after the trial grace period.</p>;
  }
  const days = daysUntil(entitlement.uninstallAt);
  return (
    <p className="mt-3 text-sm text-fg-subtle">
      Automatic uninstall on {formatDate(entitlement.uninstallAt)}
      {days !== null && days >= 0 ? ` (in ${days} day${days === 1 ? "" : "s"})` : ""}.
    </p>
  );
}
