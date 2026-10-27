import { KeyRound, ShieldCheck, Smartphone } from "lucide-react";
import { useState, type FormEvent } from "react";
import { errorMessage } from "../../api/client";
import { Button, Field, Input } from "../../components";
import { CopyButton } from "../../components/CopyButton";
import { QrCode } from "../../components/QrCode";
import { useConfirmMfaSetup, useStartMfaSetup } from "./hooks";

/** The secret in groups of four, easier to type into an authenticator app by hand. */
function grouped(secret: string): string {
  return secret.replace(/(.{4})/g, "$1 ").trim();
}

/** A 6-digit code box shared by setup, turning MFA off and the step-up prompt. */
export function CodeInput({ value, onChange, label = "6-digit code", error, autoFocus }: { value: string; onChange: (v: string) => void; label?: string; error?: string | null; autoFocus?: boolean }) {
  return (
    <Field label={label} error={error ?? undefined}>
      {(p) => (
        <Input
          {...p}
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="[0-9]*"
          maxLength={6}
          className="w-40 font-mono tracking-[0.3em]"
          value={value}
          autoFocus={autoFocus}
          onChange={(e) => onChange(e.target.value.replace(/\D/g, ""))}
        />
      )}
    </Field>
  );
}

/**
 * Authenticator app setup: start → scan the QR code (or type the key) → confirm with a code.
 * The secret is shown only here, once; the server keeps it encrypted.
 */
export function MfaSetup({ onDone, onCancel }: { onDone?: () => void; onCancel?: () => void }) {
  const start = useStartMfaSetup();
  const confirm = useConfirmMfaSetup();
  const [code, setCode] = useState("");
  const enrollment = start.data;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (code.length !== 6) return;
    confirm.mutate(code, { onSuccess: () => onDone?.(), onError: () => setCode("") });
  };

  if (!enrollment) {
    return (
      <div className="space-y-3">
        <p className="text-sm text-fg-muted">
          Each sign-in will ask for your password and a 6-digit code from an authenticator app on your phone, such as Microsoft Authenticator, Google Authenticator, Authy or 1Password.
        </p>
        {start.error ? (
          <p role="alert" className="text-sm text-sev-critical">
            {errorMessage(start.error)}
          </p>
        ) : null}
        <div className="flex flex-wrap gap-2">
          <Button variant="primary" icon={Smartphone} loading={start.isPending} onClick={() => start.mutate()}>
            Set up authenticator app
          </Button>
          {onCancel ? (
            <Button variant="secondary" onClick={onCancel}>
              Cancel
            </Button>
          ) : null}
        </div>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-[auto_minmax(0,1fr)]">
      <div className="flex flex-col items-center gap-2">
        <QrCode value={enrollment.otpauthUri} size={196} label="QR code for your authenticator app" />
        <span className="text-2xs text-fg-subtle">Scan with your authenticator app</span>
      </div>
      <div className="space-y-3">
        <ol className="list-decimal space-y-1 pl-5 text-sm text-fg-muted">
          <li>Open your authenticator app and add an account.</li>
          <li>Scan the QR code. If you can't scan it, choose to enter a setup key and type the key below.</li>
          <li>Enter the 6-digit code the app shows to finish.</li>
        </ol>
        <div>
          <span className="mb-1 flex items-center gap-1 text-2xs font-medium uppercase tracking-wide text-fg-muted">
            <KeyRound size={12} aria-hidden /> Setup key
          </span>
          <div className="flex flex-wrap items-center gap-2">
            <code className="rounded border border-line bg-surface-2 px-2 py-1 font-mono text-sm text-fg" data-testid="mfa-secret">
              {grouped(enrollment.secret)}
            </code>
            <CopyButton value={enrollment.secret} label="Copy key" />
          </div>
        </div>
        <form onSubmit={submit} className="flex flex-wrap items-end gap-2">
          <CodeInput value={code} onChange={setCode} error={confirm.error ? errorMessage(confirm.error) : null} autoFocus />
          <Button type="submit" variant="primary" icon={ShieldCheck} loading={confirm.isPending} disabled={code.length !== 6}>
            Turn on MFA
          </Button>
          {onCancel ? (
            <Button type="button" variant="secondary" onClick={onCancel}>
              Cancel
            </Button>
          ) : null}
        </form>
      </div>
    </div>
  );
}
