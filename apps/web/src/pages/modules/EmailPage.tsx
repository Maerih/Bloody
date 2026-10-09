import type { Alert } from "@bloody/contracts";
import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { AlertsLens } from "../../features/alerts/AlertsLens";
import { CategorySummary } from "../../features/alerts/CategorySummary";
import { EventsLens } from "../../features/events/EventsLens";
import { ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { alertDomain } from "../../lib/domains";
import { EMAIL_DETECTIONS, matchCategory } from "../../lib/classify";

/** No open-source mail engine is in the default catalogue: mail telemetry arrives from the gateway's audit / message-trace logs. */
const MAIL_ENGINES: string[] = [];
const isEmailAlert = (a: Alert) => alertDomain(a) === "email" || matchCategory(a, EMAIL_DETECTIONS) !== null;
const inCategory = (key: string) => (a: Alert) => matchCategory(a, EMAIL_DETECTIONS)?.category.key === key;
const label = (e: { labels?: Record<string, string> }, ...keys: string[]) => keys.map((k) => e.labels?.[k]).find((v) => v !== undefined && v !== "") ?? null;
const sender = (e: Parameters<typeof label>[0] & { user?: { email?: string } }) => label(e, "email.from", "mail.from", "sender") ?? e.user?.email ?? null;
const senderDomain = (e: Parameters<typeof sender>[0]) => sender(e)?.split("@")[1]?.toLowerCase() ?? null;

function EmailThreats() {
  const [params, setParams] = useSearchParams();
  const category = EMAIL_DETECTIONS.some((c) => c.key === params.get("category")) ? params.get("category") : null;
  const select = useCallback(
    (k: string | null) => {
      const next = new URLSearchParams(params);
      if (k) next.set("category", k);
      else next.delete("category");
      setParams(next, { replace: true });
    },
    [params, setParams],
  );
  const predicate = useMemo(() => (category ? inCategory(category) : isEmailAlert), [category]);
  return (
    <>
      <CategorySummary categories={EMAIL_DETECTIONS} predicate={isEmailAlert} selected={category} onSelect={select} />
      <AlertsLens title="Email threats" predicate={predicate} categories={EMAIL_DETECTIONS} engines={MAIL_ENGINES} emptyTitle="No email threats detected" description="Phishing, impersonation and malicious attachments detected from mail-gateway logs and user reports." savedViewsKey="mail-alerts" />
    </>
  );
}

/** Email security workspace: threats by category, quarantine, reported phishing, impersonation, mail flow. */
export default function EmailPage() {
  return (
    <ModuleWorkspace
      moduleId="mail"
      aliases={{ "/email": "" }}
      sections={{
        "": () => (
          <div className="space-y-4">
            <EmailThreats />
          </div>
        ),
        quarantine: () => (
          <EventsLens
            title="Quarantined messages"
            query="category:email AND action:(quarantine OR quarantined OR blocked OR rejected)"
            engines={MAIL_ENGINES}
            defaultRange={{ preset: "7d" }}
            description="Messages held or rejected by the mail gateway. Release decisions happen in the gateway; every action is logged here."
            aggregations={[
              { title: "Sender domains", field: "labels.email.from", value: senderDomain },
              { title: "Recipients", field: "labels.email.to", value: (e) => label(e, "email.to", "mail.to", "recipient") },
              { title: "Verdicts", field: "action", value: (e) => e.action ?? null },
            ]}
          />
        ),
        reported: () => (
          <div className="space-y-4">
            <AlertsLens title="Phishing reported or detected" predicate={(a) => ["phishing_link", "phishing", "malicious_attachment"].includes(matchCategory(a, EMAIL_DETECTIONS)?.category.key ?? "")} categories={EMAIL_DETECTIONS} engines={MAIL_ENGINES} emptyTitle="No reported phishing" savedViewsKey="mail-reported" />
            <EventsLens title="User reports" query="category:email AND action:(reported OR user-reported OR report-phish)" engines={MAIL_ENGINES} defaultRange={{ preset: "30d" }} aggregations={[{ title: "Reporters", field: "user.email", value: (e) => e.user?.email ?? null }, { title: "Sender domains", field: "labels.email.from", value: senderDomain }]} />
          </div>
        ),
        impersonation: () => <AlertsLens title="Impersonation & BEC" predicate={inCategory("impersonation")} categories={EMAIL_DETECTIONS} engines={MAIL_ENGINES} emptyTitle="No impersonation detected" description="Display-name spoofing, look-alike domains and business-email-compromise patterns." savedViewsKey="mail-impersonation" />,
        flow: () => (
          <EventsLens
            title="Mail flow"
            query="category:email"
            engines={MAIL_ENGINES}
            aggregations={[
              { title: "Sender domains", field: "labels.email.from", value: senderDomain },
              { title: "Directions", field: "network.direction", value: (e) => e.network?.direction ?? null },
              { title: "Outcomes", field: "outcome", value: (e) => e.outcome ?? null },
            ]}
          />
        ),
      }}
    />
  );
}
