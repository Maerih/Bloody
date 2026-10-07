import { Lock, Plug, Sparkles } from "lucide-react";
import { useLocation } from "react-router-dom";
import { findNavMatch } from "../app/navigation";
import { useSession } from "../app/session";
import { StatusBadge } from "../components/Badge";
import { ButtonLink } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";
import { Tabs } from "../components/Tabs";
import { railItemsFor } from "../layout/LeftRail";
import { useNavigate } from "react-router-dom";

/**
 * Generic module workspace shell used for every navigable path that does not yet have a
 * dedicated page (part B replaces these routes). It shows real entitlement state and the
 * module's sub-pages — never placeholder numbers.
 */
export default function ModulePlaceholderPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const session = useSession();
  const { module, item } = findNavMatch(location.pathname);
  const title = item?.label ?? module?.name ?? "Page";
  const state = module?.module ? session.moduleState(module.module) : "active";
  const enabled = !module?.module || session.isModuleEnabled(module.module);
  const subItems = module ? railItemsFor(module, session) : [];
  const Icon = item?.icon ?? module?.icon ?? Plug;

  return (
    <div>
      <PageHeader
        title={title}
        subtitle={item?.description ?? module?.description}
        breadcrumbs={module && item && item.path !== module.path ? [{ label: module.name, href: module.path }, { label: item.label }] : module ? [{ label: module.name }] : undefined}
        actions={module?.module ? <StatusBadge status={state} /> : null}
      >
        {enabled && subItems.length > 1 ? (
          <Tabs
            ariaLabel={`${module?.name ?? ""} sections`}
            value={item?.path ?? ""}
            onChange={(path) => navigate(path)}
            tabs={subItems.map((s) => ({ id: s.path, label: s.label, icon: s.icon }))}
          />
        ) : null}
      </PageHeader>
      <div className="rounded border border-line bg-surface shadow-card">
        {!enabled ? (
          <EmptyState
            icon={Lock}
            tone="locked"
            title={`${module?.name ?? title} is not enabled for ${session.account.name}`}
            description={
              state === "trial_ended"
                ? "Your trial has ended. Subscribe to keep using this module."
                : state === "available"
                  ? "Start a free trial to explore this module with your own data."
                  : "This module is not included in your current plan."
            }
            action={
              <ButtonLink to={`/trials?module=${module?.module ?? ""}`} variant="primary" size="sm">
                {state === "available" ? "Start trial" : "View plans & trials"}
              </ButtonLink>
            }
          />
        ) : (
          <EmptyState
            icon={Icon}
            title={`No ${title.toLowerCase()} data to show yet`}
            description="This workspace fills in automatically as connected integrations and agents report for the selected organization."
            action={
              <>
                <ButtonLink to="/integrations" size="sm" icon={Plug}>
                  Configure integrations
                </ButtonLink>
                {session.isModuleEnabled("ai_soc") ? (
                  <ButtonLink to="/ai" size="sm" icon={Sparkles}>
                    Ask AI SOC
                  </ButtonLink>
                ) : null}
              </>
            }
          />
        )}
      </div>
    </div>
  );
}
