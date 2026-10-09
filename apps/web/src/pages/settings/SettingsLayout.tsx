import type { Permission } from "@bloody/contracts";
import { clsx } from "clsx";
import { Archive, BrainCircuit, CreditCard, KeyRound, LayoutGrid, ScrollText, SlidersHorizontal, UserRound, Users, Webhook, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { ORG_PARAM, useSession } from "../../app/session";

export interface SettingsSection {
  path: string;
  label: string;
  icon: LucideIcon;
  description: string;
  /** Shown when the principal holds this permission for any organization (or tenant-wide). */
  permission?: Permission;
  /** Extra paths that highlight this section. */
  aliases?: string[];
}

export const SETTINGS_SECTIONS: SettingsSection[] = [
  { path: "/settings", label: "Overview", icon: LayoutGrid, description: "Account, plan and configuration at a glance" },
  { path: "/settings/users", label: "Users & Teams", icon: Users, description: "People, teams and role bindings per organization", permission: "user:read", aliases: ["/users"] },
  { path: "/settings/api-credentials", label: "API Credentials", icon: KeyRound, description: "Service accounts and ingestion API keys", permission: "apikey:write" },
  { path: "/settings/ai", label: "AI Models & Policies", icon: BrainCircuit, description: "Local and cloud model providers, tool tiers, privacy", permission: "ai:configure", aliases: ["/ai/providers", "/ai/policies"] },
  { path: "/settings/notifications", label: "Notification Channels", icon: Webhook, description: "Email (SMTP), Slack, Teams, webhook and syslog delivery" },
  { path: "/settings/billing", label: "Billing & Usage", icon: CreditCard, description: "Plan, limits and usage meters", permission: "billing:read", aliases: ["/billing"] },
  { path: "/settings/audit", label: "Audit Log", icon: ScrollText, description: "Every mutating action with actor, target and request id", permission: "audit:read", aliases: ["/audit"] },
  { path: "/settings/preferences", label: "Preferences", icon: UserRound, description: "Theme, density and default dashboard view", aliases: ["/preferences"] },
  { path: "/settings/data-archive", label: "Data & Retention", icon: Archive, description: "Event retention per organization and archive tiers" },
];

export function visibleSettingsSections(session: ReturnType<typeof useSession>): SettingsSection[] {
  return SETTINGS_SECTIONS.filter((s) => !s.permission || session.canAnywhere(s.permission));
}

function isActive(section: SettingsSection, pathname: string): boolean {
  const paths = [section.path, ...(section.aliases ?? [])];
  return paths.some((p) => (p === "/settings" ? pathname === "/settings" || pathname === "/settings/" : pathname === p || pathname.startsWith(`${p}/`)));
}

/** Settings frame: a vertical section nav beside the section page (which keeps its own header). */
export function SettingsLayout({ children }: { children: ReactNode }) {
  const session = useSession();
  const location = useLocation();
  const org = new URLSearchParams(location.search).get(ORG_PARAM);
  const sections = visibleSettingsSections(session);
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[200px_minmax(0,1fr)]">
      <nav aria-label="Settings" className="lg:sticky lg:top-2 lg:self-start">
        <h2 className="mb-1 px-2 text-2xs font-semibold uppercase tracking-wide text-fg-subtle">
          <SlidersHorizontal size={11} className="mr-1 inline" aria-hidden />
          Settings
        </h2>
        <ul className="flex gap-1 overflow-x-auto pb-1 lg:block lg:space-y-0.5 lg:overflow-visible">
          {sections.map((s) => {
            const active = isActive(s, location.pathname);
            return (
              <li key={s.path} className="shrink-0">
                <NavLink
                  to={{ pathname: s.path, search: org ? `?${ORG_PARAM}=${encodeURIComponent(org)}` : "" }}
                  aria-current={active ? "page" : undefined}
                  className={clsx("flex items-center gap-2 rounded px-2 py-1.5 text-sm", active ? "bg-primary-soft font-medium text-primary" : "text-fg-muted hover:bg-surface-2 hover:text-fg")}
                >
                  <s.icon size={14} aria-hidden />
                  <span className="truncate">{s.label}</span>
                </NavLink>
              </li>
            );
          })}
        </ul>
      </nav>
      <div className="min-w-0">{children}</div>
    </div>
  );
}
