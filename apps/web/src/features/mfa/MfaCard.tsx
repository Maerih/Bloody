import { ShieldCheck, ShieldOff } from "lucide-react";
import { useState, type FormEvent } from "react";
import { errorMessage } from "../../api/client";
import { useSession } from "../../app/session";
import { Badge, Button, Card } from "../../components";
import { useTurnOffMfa } from "./hooks";
import { CodeInput, MfaSetup } from "./MfaSetup";

/** Preferences card: your own multi-factor authentication (authenticator app). */
export function MfaCard() {
  const { me } = useSession();
  const turnOff = useTurnOffMfa();
  const [confirmingOff, setConfirmingOff] = useState(false);
  const [code, setCode] = useState("");
  const enabled = me.user?.mfaEnabled === true;
  const required = me.account.requireMfa === true;

  const submitOff = (e: FormEvent) => {
    e.preventDefault();
    if (code.length !== 6) return;
    turnOff.mutate(code, {
      onSuccess: () => {
        setConfirmingOff(false);
        setCode("");
      },
      onError: () => setCode(""),
    });
  };

  return (
    <Card
      title="Multi-factor authentication"
      info="A code from an authenticator app on your phone, asked at every password sign-in and before sensitive changes."
      actions={enabled ? <Badge tone="success" icon={ShieldCheck}>On</Badge> : <Badge tone={required ? "danger" : "warning"} icon={ShieldOff}>Off</Badge>}
    >
      {me.session?.method === "sandbox" || !me.user ? (
        <p className="text-sm text-fg-muted">Not available in the demo sandbox.</p>
      ) : enabled ? (
        <div className="space-y-3">
          <p className="text-sm text-fg-muted">
            Every sign-in with your password asks for a code from your authenticator app.
            {me.session?.method === "oidc" ? " You signed in with single sign-on this time, so your identity provider's own checks applied." : ""}
          </p>
          {required ? (
            <p className="text-sm text-fg-muted">Your account requires MFA, so it stays on. Changing phones? Ask an administrator to reset it, then set it up again on the new phone.</p>
          ) : confirmingOff ? (
            <form onSubmit={submitOff} className="flex flex-wrap items-end gap-2">
              <CodeInput value={code} onChange={setCode} label="Code from your authenticator app" error={turnOff.error ? errorMessage(turnOff.error) : null} autoFocus />
              <Button type="submit" variant="danger" loading={turnOff.isPending} disabled={code.length !== 6}>
                Turn off MFA
              </Button>
              <Button type="button" variant="secondary" onClick={() => setConfirmingOff(false)}>
                Cancel
              </Button>
            </form>
          ) : (
            <Button variant="secondary" icon={ShieldOff} onClick={() => setConfirmingOff(true)}>
              Turn off
            </Button>
          )}
        </div>
      ) : (
        <MfaSetup />
      )}
    </Card>
  );
}
