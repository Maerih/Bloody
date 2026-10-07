import { KeyRound, LogIn, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { errorMessage, isApiError } from "../api/client";
import { useLogin, useMe, useOidcStart } from "../api/hooks";
import { Button } from "../components/Button";
import { Field, Input } from "../components/Form";
import { Logo } from "../components/Logo";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { safeInternalPath } from "../lib/entityLinks";

/** Sign in: email + password (+ TOTP when required) or SSO via the configured OIDC provider. */
export default function LoginPage() {
  useDocumentTitle("Sign in");
  const [params] = useSearchParams();
  const next = safeInternalPath(params.get("next"));
  const me = useMe();
  const login = useLogin();
  const oidc = useOidcStart();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [ssoMessage, setSsoMessage] = useState<string | null>(null);
  const totpRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (mfaRequired) totpRef.current?.focus();
  }, [mfaRequired]);

  if (me.isSuccess) return <Navigate to={next} replace />;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password) return;
    login.mutate(
      { email: email.trim(), password, ...(mfaRequired && totp ? { totp: totp.trim() } : {}) },
      {
        onSuccess: (res) => {
          if (res?.mfaRequired) setMfaRequired(true);
          else void me.refetch();
        },
      },
    );
  };

  const startSso = () => {
    setSsoMessage(null);
    oidc.mutate(
      { returnTo: next },
      {
        onSuccess: (res) => {
          const url = res?.authorizationUrl ?? res?.url;
          if (url && /^https?:\/\//i.test(url)) window.location.assign(url);
          else setSsoMessage("Single sign-on did not return an authorization URL. Contact your administrator.");
        },
        onError: (err) => {
          setSsoMessage(
            isApiError(err) && (err.isNotFound || err.status === 501)
              ? "Single sign-on is not configured for this environment. Sign in with your email and password."
              : errorMessage(err),
          );
        },
      },
    );
  };

  const loginError = login.isError
    ? isApiError(login.error) && login.error.status === 401
      ? "Incorrect email, password or verification code."
      : errorMessage(login.error)
    : null;

  return (
    <div className="grid min-h-screen grid-cols-1 bg-canvas lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
      <aside className="relative hidden flex-col justify-between overflow-hidden bg-topbar p-10 text-topbar-fg lg:flex">
        <Logo inverse />
        <div className="max-w-md">
          <h1 className="font-display text-3xl font-bold leading-tight text-white">One Command Center for every security signal.</h1>
          <p className="mt-3 text-md text-topbar-muted">
            Endpoint, identity, network, SIEM, exposure, cloud, threat intelligence, DFIR, SOAR and AI-driven operations — through one Security Graph and one Risk Engine.
          </p>
        </div>
        <ul className="space-y-2 text-sm text-topbar-muted">
          <li className="flex items-center gap-2">
            <ShieldCheck size={14} aria-hidden className="text-healthy" /> Strict tenant isolation, RBAC and full audit trail
          </li>
          <li className="flex items-center gap-2">
            <KeyRound size={14} aria-hidden className="text-healthy" /> SSO, MFA and scoped API credentials
          </li>
        </ul>
        <div className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-brand/20 blur-3xl" aria-hidden />
      </aside>
      <main className="flex items-center justify-center p-6">
        <div className="w-full max-w-sm">
          <div className="mb-6 lg:hidden">
            <Logo />
          </div>
          <h2 className="font-display text-2xl font-bold text-fg">Sign in</h2>
          <p className="mt-1 text-base text-fg-muted">Access your Bloody Command Center.</p>
          <form className="mt-6 space-y-3" onSubmit={submit} noValidate>
            <Field label="Work email" required>
              {(p) => <Input {...p} type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} disabled={mfaRequired} autoFocus required />}
            </Field>
            <Field label="Password" required>
              {(p) => <Input {...p} type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} disabled={mfaRequired} required />}
            </Field>
            {mfaRequired ? (
              <Field label="Verification code" required hint="Enter the 6-digit code from your authenticator app.">
                {(p) => (
                  <Input
                    {...p}
                    ref={totpRef}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    pattern="[0-9]*"
                    maxLength={8}
                    value={totp}
                    onChange={(e) => setTotp(e.target.value.replace(/\D/g, ""))}
                  />
                )}
              </Field>
            ) : null}
            {loginError ? (
              <p role="alert" className="rounded border border-sev-critical/30 bg-sev-critical/5 px-2.5 py-2 text-sm text-sev-critical">
                {loginError}
              </p>
            ) : null}
            <Button type="submit" variant="primary" size="lg" icon={LogIn} className="w-full" loading={login.isPending} disabled={!email.trim() || !password || (mfaRequired && totp.length < 6)}>
              {mfaRequired ? "Verify and sign in" : "Sign in"}
            </Button>
          </form>
          <div className="my-5 flex items-center gap-3 text-xs text-fg-subtle">
            <span className="h-px flex-1 bg-line" /> or <span className="h-px flex-1 bg-line" />
          </div>
          <Button size="lg" icon={KeyRound} className="w-full" onClick={startSso} loading={oidc.isPending}>
            Sign in with SSO
          </Button>
          {ssoMessage ? (
            <p role="status" className="mt-2 text-sm text-fg-muted">
              {ssoMessage}
            </p>
          ) : null}
          <p className="mt-8 text-xs text-fg-subtle">Access is logged and monitored. Unauthorized use is prohibited.</p>
        </div>
      </main>
    </div>
  );
}
