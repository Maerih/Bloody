import type { ModuleKey } from "@bloody/contracts";
import { Plug, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { useSession } from "../app/session";
import { connectHref, engineByKey, enginesForModule } from "../lib/engines";
import { ButtonLink } from "./Button";
import { EmptyState } from "./EmptyState";

/**
 * Real empty state for module lenses: explains which engine feeds this view and links to the
 * Integrations Hub with that engine's configure dialog open ("Connect Wazuh").
 */
export function ConnectEngineEmptyState({
  title,
  description,
  engines,
  module,
  icon = Plug,
  compact = false,
  extraAction,
}: {
  title: ReactNode;
  description?: ReactNode;
  /** Engine keys (ENGINES[].key); defaults to the module's core engines. */
  engines?: string[];
  module?: ModuleKey;
  icon?: LucideIcon;
  compact?: boolean;
  extraAction?: ReactNode;
}) {
  const session = useSession();
  const defs = (engines ? engines.map((k) => engineByKey(k)).filter((e) => e !== undefined) : module ? enginesForModule(module).filter((e) => e.core) : []).slice(0, 3);
  const canConfigure = session.canAnywhere("integration:write");
  return (
    <EmptyState
      icon={icon}
      compact={compact}
      title={title}
      description={description ?? (defs.length > 0 ? `This view fills in when ${defs.map((d) => d.name).join(", ")} ${defs.length === 1 ? "is" : "are"} connected and reporting for the selected organization.` : undefined)}
      action={
        <>
          {defs.map((d, i) => (
            <ButtonLink key={d.key} to={connectHref(d.key)} size="sm" variant={i === 0 ? "primary" : "secondary"} icon={Plug}>
              {canConfigure ? `Connect ${d.name}` : `About ${d.name}`}
            </ButtonLink>
          ))}
          {defs.length === 0 ? (
            <ButtonLink to="/integrations" size="sm" icon={Plug}>
              Integrations Hub
            </ButtonLink>
          ) : null}
          {extraAction}
        </>
      }
    />
  );
}
