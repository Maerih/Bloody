import { useCallback, useMemo } from "react";
import { useUsers } from "../../api/hooks";
import type { UserSummary } from "../../api/types";
import { useSession } from "../../app/session";

/** Strip a "user:" / "service:" principal prefix. */
export function actorId(actor: string): string {
  const idx = actor.indexOf(":");
  return idx > 0 && /^(user|service|apikey|api_key)$/.test(actor.slice(0, idx)) ? actor.slice(idx + 1) : actor;
}

export function userLabel(u: Pick<UserSummary, "displayName" | "email">): string {
  return u.displayName ?? u.email;
}

/**
 * Resolve audit-style actor references ("user:<uuid>", "<uuid>", "ai:…", "playbook:…", "system")
 * to display names using the tenant's user directory (only when the principal may read users).
 */
export function useActorName(): { name: (actor: string | null | undefined) => string; users: UserSummary[]; byId: Map<string, UserSummary> } {
  const session = useSession();
  const users = useUsers({ enabled: session.canAnywhere("user:read") });
  const byId = useMemo(() => new Map((users.data ?? []).map((u) => [u.id, u])), [users.data]);
  const name = useCallback(
    (actor: string | null | undefined): string => {
      if (!actor) return "System";
      if (actor === "system") return "System";
      if (actor.startsWith("ai")) return "AI SOC analyst";
      if (actor.startsWith("playbook:")) return `Playbook ${actor.slice("playbook:".length)}`;
      const id = actorId(actor);
      if (id === session.principal.id) return session.principal.displayName ?? session.principal.email ?? "You";
      const u = byId.get(id);
      return u ? userLabel(u) : actor;
    },
    [byId, session.principal],
  );
  return { name, users: users.data ?? [], byId };
}
