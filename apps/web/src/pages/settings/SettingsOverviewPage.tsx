import { PLANS } from "@bloody/contracts";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { useAiProviders, useApiKeys, useNotificationChannels, useTeams, useUsers } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Card } from "../../components/Card";
import { DescriptionList } from "../../components/DescriptionList";
import { PageHeader } from "../../components/PageHeader";
import { effectiveProvider } from "../../lib/aiProviders";
import { formatInteger } from "../../lib/format";
import { visibleSettingsSections, type SettingsSection } from "./SettingsLayout";

function useSectionStatus(): Record<string, ReactNode> {
  const session = useSession();
  const users = useUsers({ enabled: session.canAnywhere("user:read") });
  const teams = useTeams({ enabled: session.canAnywhere("user:read") });
  const keys = useApiKeys({ enabled: session.canAnywhere("apikey:write") });
  const ai = useAiProviders({ enabled: session.canAnywhere("ai:configure") });
  const channels = useNotificationChannels();
  const effective = ai.data ? effectiveProvider(ai.data, session.organizationId) : null;
  const plan = PLANS[session.plan];
  return {
    "/settings/users": users.data ? `${formatInteger(users.data.length)} users${teams.data ? ` · ${formatInteger(teams.data.length)} teams` : ""} · ${formatInteger(users.data.filter((u) => !u.mfaEnabled).length)} without MFA` : null,
    "/settings/api-credentials": keys.data ? `${formatInteger(keys.data.filter((k) => k.active).length)} active key(s)` : null,
    "/settings/ai": ai.data ? (effective ? `Default: ${effective.name} · ${effective.model}` : <span className="text-sev-high">No model configured</span>) : null,
    "/settings/notifications": channels.data ? `${formatInteger(channels.data.filter((c) => c.enabled).length)} enabled channel(s)` : null,
    "/settings/billing": `${plan.name} plan`,
    "/settings/data-archive": `Up to ${formatInteger(plan.limits.retentionDays)} days hot retention`,
  };
}

/** /settings — account summary and a card per settings section with its live status. */
export default function SettingsOverviewPage() {
  const session = useSession();
  const status = useSectionStatus();
  const sections = visibleSettingsSections(session).filter((s) => s.path !== "/settings");
  return (
    <div>
      <PageHeader title="Settings" subtitle="Account, access, integrations, AI, notifications, billing and data policies." />
      <Card title="Account" className="mb-3">
        <DescriptionList
          items={[
            { label: "Account", value: session.account.name },
            { label: "Type", value: <Badge tone={session.account.kind === "mssp" ? "purple" : "info"}>{session.account.kind === "mssp" ? "MSSP / MDR" : "Enterprise"}</Badge> },
            { label: "Plan", value: PLANS[session.plan].name },
            { label: "Data region", value: session.account.dataRegion },
            { label: "Organizations", value: formatInteger(session.organizations.length) },
            { label: "Signed in as", value: session.principal.email ?? session.principal.displayName ?? session.principal.id },
          ]}
        />
      </Card>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
        {sections.map((s: SettingsSection) => (
          <Link key={s.path} to={s.path} className="group rounded border border-line bg-surface p-3 shadow-card transition-colors hover:border-primary/50">
            <span className="flex items-center gap-2">
              <span className="inline-flex h-7 w-7 items-center justify-center rounded bg-surface-3 text-fg-muted group-hover:text-primary" aria-hidden>
                <s.icon size={14} />
              </span>
              <span className="text-md font-semibold text-heading">{s.label}</span>
            </span>
            <span className="mt-1 block text-sm text-fg-muted">{s.description}</span>
            {status[s.path] ? <span className="mt-2 block text-xs text-fg">{status[s.path]}</span> : null}
          </Link>
        ))}
      </div>
    </div>
  );
}
