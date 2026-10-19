import { ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, errorMessage, setStepUpHandler } from "../api/client";
import { Button, Dialog, Field, Input } from "../components";

/**
 * App-wide step-up prompt. Dangerous actions (role grants, password resets, API keys, emergency
 * response, approvals) need an authenticator check in the last few minutes; when the API asks for
 * one, this dialog takes the code and the client re-sends the original request.
 */
export function StepUpDialog() {
  const [open, setOpen] = useState(false);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const resolver = useRef<((ok: boolean) => void) | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(
    () =>
      setStepUpHandler(
        () =>
          new Promise<boolean>((resolve) => {
            resolver.current = resolve;
            setCode("");
            setError(null);
            setOpen(true);
          }),
      ),
    [],
  );

  const finish = (ok: boolean) => {
    resolver.current?.(ok);
    resolver.current = null;
    setOpen(false);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (code.length < 6) return;
    setBusy(true);
    setError(null);
    try {
      await api.post("/auth/mfa/verify", { code }, { skipStepUp: true });
      finish(true);
    } catch (err) {
      setError(errorMessage(err));
      setCode("");
      inputRef.current?.focus();
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={() => finish(false)}
      size="sm"
      title="Confirm it is you"
      description="This is a sensitive change. Enter the 6-digit code from your authenticator app to continue."
      initialFocus={inputRef}
    >
      <form onSubmit={(e) => void submit(e)} className="space-y-3">
        <Field label="Authenticator code" error={error ?? undefined}>
          {(p) => (
            <Input
              {...p}
              ref={inputRef}
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]*"
              maxLength={8}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            />
          )}
        </Field>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={() => finish(false)}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" icon={ShieldCheck} loading={busy} disabled={code.length < 6}>
            Confirm
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
