import { DashboardRole } from "@bloody/contracts";
import { clsx } from "clsx";
import { Laptop, Moon, Rows2, Rows4, Sun } from "lucide-react";
import { Link } from "react-router-dom";
import { DASHBOARD_PRESETS, DASHBOARD_ROLES } from "../app/dashboardPresets";
import { useSession } from "../app/session";
import { useTheme, type Density, type ThemePreference } from "../app/theme";
import { Card } from "../components/Card";
import { DescriptionList } from "../components/DescriptionList";
import { Select } from "../components/Form";
import { PageHeader } from "../components/PageHeader";
import { ShortcutList } from "../layout/ShortcutHelpDialog";

const THEMES: { value: ThemePreference; label: string; icon: typeof Sun; hint: string }[] = [
  { value: "system", label: "System", icon: Laptop, hint: "Follow your OS setting" },
  { value: "light", label: "Light", icon: Sun, hint: "Light canvas, white cards" },
  { value: "dark", label: "Dark", icon: Moon, hint: "Low-light SOC floors" },
];

const DENSITIES: { value: Density; label: string; icon: typeof Sun; hint: string }[] = [
  { value: "comfortable", label: "Comfortable", icon: Rows2, hint: "More breathing room between rows" },
  { value: "compact", label: "Compact", icon: Rows4, hint: "More rows on screen for triage" },
];

/** Per-user UI preferences (stored in this browser). */
export default function PreferencesPage() {
  const theme = useTheme();
  const session = useSession();
  return (
    <div className="max-w-4xl">
      <PageHeader title="Preferences" subtitle="Personal settings for this browser." breadcrumbs={[{ label: "Settings", href: "/settings" }, { label: "Preferences" }]} />
      <div className="space-y-3">
        <Card title="Appearance">
          <div role="radiogroup" aria-label="Theme" className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            {THEMES.map((t) => {
              const selected = theme.preference === t.value;
              return (
                <button
                  key={t.value}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  onClick={() => theme.setPreference(t.value)}
                  className={clsx(
                    "flex items-center gap-3 rounded border p-3 text-left transition-colors",
                    selected ? "border-primary bg-primary-soft" : "border-line hover:border-line-strong",
                  )}
                >
                  <t.icon size={18} aria-hidden className={selected ? "text-primary" : "text-fg-muted"} />
                  <span>
                    <span className="block text-base font-medium text-fg">{t.label}</span>
                    <span className="block text-xs text-fg-muted">{t.hint}</span>
                  </span>
                </button>
              );
            })}
          </div>
        </Card>
        <Card title="Density" info="Row spacing of tables across the Command Center.">
          <div role="radiogroup" aria-label="Density" className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {DENSITIES.map((d) => {
              const selected = theme.density === d.value;
              return (
                <button
                  key={d.value}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  onClick={() => theme.setDensity(d.value)}
                  className={clsx("flex items-center gap-3 rounded border p-3 text-left transition-colors", selected ? "border-primary bg-primary-soft" : "border-line hover:border-line-strong")}
                >
                  <d.icon size={18} aria-hidden className={selected ? "text-primary" : "text-fg-muted"} />
                  <span>
                    <span className="block text-base font-medium text-fg">{d.label}</span>
                    <span className="block text-xs text-fg-muted">{d.hint}</span>
                  </span>
                </button>
              );
            })}
          </div>
        </Card>
        <Card title="Command Center view" info="Selects and orders the Command Center widgets for your role.">
          <label className="flex max-w-md flex-col gap-1 text-sm text-fg-muted">
            Default dashboard view
            <Select value={session.dashboardRole} onChange={(e) => session.setDashboardRole(DashboardRole.parse(e.target.value))}>
              {DASHBOARD_ROLES.map((r) => (
                <option key={r} value={r}>
                  {DASHBOARD_PRESETS[r].label}
                </option>
              ))}
            </Select>
          </label>
          <p className="mt-2 text-sm text-fg-muted">{DASHBOARD_PRESETS[session.dashboardRole].description}</p>
        </Card>
        <Card title="Notifications" info="Email, Slack and Teams delivery is configured per account in Notification Channels and Automation Rules.">
          <p className="text-sm text-fg-muted">
            Choose which events reach you by email or chat in{" "}
            <Link to="/automations" className="text-primary hover:underline">
              Automation rules
            </Link>{" "}
            and{" "}
            <Link to="/automations?tab=channels" className="text-primary hover:underline">
              Notification channels
            </Link>
            . Scheduled reports are managed in{" "}
            <Link to="/reports" className="text-primary hover:underline">
              Reports
            </Link>
            .
          </p>
        </Card>
        <Card title="Profile">
          <DescriptionList
            items={[
              { label: "Name", value: session.principal.displayName ?? null },
              { label: "Email", value: session.principal.email ?? null },
              { label: "Account", value: session.account.name },
              { label: "Roles", value: [...new Set(session.principal.bindings.map((b) => b.role.replace(/_/g, " ")))].join(", ") || null },
            ]}
          />
        </Card>
        <Card title="Keyboard shortcuts">
          <ShortcutList />
        </Card>
      </div>
    </div>
  );
}
