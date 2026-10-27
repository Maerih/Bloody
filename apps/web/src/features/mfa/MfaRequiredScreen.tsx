import { LogOut, ShieldCheck } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useLogout } from "../../api/hooks";
import type { MeResponse } from "../../api/types";
import { Button, LogoMark } from "../../components";
import { MfaSetup } from "./MfaSetup";

/**
 * Shown instead of the console when the account requires MFA and this person has not set it up.
 * The API answers nothing else for them until they do.
 */
export function MfaRequiredScreen({ me, onDone }: { me: MeResponse; onDone: () => void }) {
  const logout = useLogout();
  const navigate = useNavigate();
  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas p-4">
      <main className="w-full max-w-2xl rounded-lg border border-line bg-surface p-6 shadow-card">
        <div className="mb-4 flex items-center gap-3">
          <LogoMark size={32} />
          <div>
            <h1 className="flex items-center gap-2 text-lg font-semibold text-heading">
              <ShieldCheck size={18} aria-hidden className="text-primary" /> Set up multi-factor authentication
            </h1>
            <p className="text-sm text-fg-muted">
              {me.account.name} requires an authenticator app for every sign-in. Set it up now to continue{me.user?.email ? ` as ${me.user.email}` : ""}.
            </p>
          </div>
        </div>
        <MfaSetup onDone={onDone} />
        <div className="mt-6 border-t border-line pt-3">
          <Button variant="ghost" size="sm" icon={LogOut} loading={logout.isPending} onClick={() => logout.mutate(undefined, { onSettled: () => navigate("/login", { replace: true }) })}>
            Sign out
          </Button>
        </div>
      </main>
    </div>
  );
}
