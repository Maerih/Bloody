import { ShieldCheck } from "lucide-react";
import { errorMessage } from "../../api/client";
import { useSession } from "../../app/session";
import { Button } from "../../components";
import { useMfaPolicy, useSetMfaPolicy } from "./hooks";

/** Account-wide switch: require an authenticator app for every password sign-in. */
export function MfaPolicyCard() {
  const session = useSession();
  const canEdit = session.can("settings:write", null);
  const policy = useMfaPolicy(session.canAnywhere("user:read"));
  const set = useSetMfaPolicy();
  if (!policy.data) return null;
  const { requireMfa, usersWithMfa, usersWithoutMfa } = policy.data;
  const selfReady = session.me.user?.mfaEnabled === true;
  return (
    <section aria-label="MFA policy" className="mb-3 flex flex-wrap items-center gap-3 rounded border border-line bg-surface px-4 py-3 shadow-card">
      <ShieldCheck size={20} aria-hidden className={requireMfa ? "text-healthy" : "text-fg-muted"} />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-heading">{requireMfa ? "MFA is required for everyone" : "MFA is optional"}</p>
        <p className="text-xs text-fg-muted">
          {usersWithMfa} {usersWithMfa === 1 ? "person uses" : "people use"} an authenticator app, {usersWithoutMfa} {usersWithoutMfa === 1 ? "does" : "do"} not.
          {requireMfa ? " People without one are asked to set it up at their next sign-in." : " Requiring it asks everyone without one to set it up before they can continue."}
          {" Single sign-on users follow their identity provider's MFA."}
        </p>
        {set.error ? (
          <p role="alert" className="mt-1 text-xs text-sev-critical">
            {errorMessage(set.error)}
          </p>
        ) : null}
        {canEdit && !requireMfa && !selfReady ? <p className="mt-1 text-xs text-fg-subtle">Set up MFA for yourself first in Preferences.</p> : null}
      </div>
      {canEdit ? (
        <Button size="sm" variant={requireMfa ? "secondary" : "primary"} loading={set.isPending} disabled={!requireMfa && !selfReady} onClick={() => set.mutate(!requireMfa)}>
          {requireMfa ? "Make MFA optional" : "Require MFA for everyone"}
        </Button>
      ) : null}
    </section>
  );
}
