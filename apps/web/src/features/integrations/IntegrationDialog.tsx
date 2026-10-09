import type { EngineDefinition } from "@bloody/contracts";
import { ShieldCheck, TriangleAlert } from "lucide-react";
import { useState } from "react";
import { errorMessage } from "../../api/client";
import { useCreateIntegration, useUpdateIntegration } from "../../api/hooks";
import type { CreateIntegrationInput, IntegrationView } from "../../api/types";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Checkbox, Field, Input, Textarea } from "../../components/Form";
import { OrganizationSelect, useDefaultOrganization } from "../../components/OrganizationSelect";
import { useSession } from "../../app/session";
import { Dialog } from "../../components/Overlay";
import { MODE_LABELS, moduleName } from "../../lib/engines";

/** Engines that actively probe targets: scanning requires an authorized scope and a rate limit. */
export const SCANNING_ENGINES = new Set(["nuclei", "subfinder", "amass", "greenbone"]);

export interface ScanScope {
  targets: string[];
  exclusions: string[];
  ratePerSecond: number;
  authorization: { reference: string; approvedBy: string; expiresAt: string };
}

export function readScanScope(config: Record<string, unknown> | undefined): ScanScope | null {
  const s = config?.scope;
  if (!s || typeof s !== "object") return null;
  const scope = s as Partial<ScanScope>;
  if (!Array.isArray(scope.targets)) return null;
  return {
    targets: scope.targets.map(String),
    exclusions: Array.isArray(scope.exclusions) ? scope.exclusions.map(String) : [],
    ratePerSecond: typeof scope.ratePerSecond === "number" ? scope.ratePerSecond : 0,
    authorization: {
      reference: String(scope.authorization?.reference ?? ""),
      approvedBy: String(scope.authorization?.approvedBy ?? ""),
      expiresAt: String(scope.authorization?.expiresAt ?? ""),
    },
  };
}

const TARGET_RE = /^(\*\.)?([a-z0-9-]+\.)+[a-z]{2,63}$|^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/i;

function lines(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((l) => l.trim())
    .filter(Boolean);
}

export interface IntegrationFormErrors {
  name?: string;
  endpoint?: string;
  credential?: string;
  targets?: string;
  rate?: string;
  authorization?: string;
}

/** Validate the configure form; ASM/scanner engines additionally need an authorized scope. */
export function validateIntegrationForm(
  engine: EngineDefinition,
  v: { name: string; endpoint: string; credential: string; hasStoredCredential: boolean; targets: string; rate: string; authRef: string; approvedBy: string; authExpires: string },
): IntegrationFormErrors {
  const e: IntegrationFormErrors = {};
  if (!v.name.trim()) e.name = "Name is required";
  const endpoint = v.endpoint.trim();
  const needsEndpoint = engine.mode === "network_api";
  if (needsEndpoint && !endpoint) e.endpoint = `${engine.name} is reached over its network API — enter its base URL`;
  if (endpoint) {
    try {
      const u = new URL(endpoint);
      if (u.protocol !== "https:" && u.protocol !== "http:") e.endpoint = "Use an http(s) URL";
      else if (u.username || u.password) e.endpoint = "Do not embed credentials in the URL";
    } catch {
      e.endpoint = "Enter a valid URL";
    }
  }
  if (engine.key === "copilot" && !v.credential.trim() && !v.hasStoredCredential) e.credential = "CoPilot requires an API token";
  if (SCANNING_ENGINES.has(engine.key)) {
    const targets = lines(v.targets);
    if (targets.length === 0) e.targets = "List at least one authorized target (domain, wildcard or CIDR)";
    else {
      const bad = targets.find((t) => !TARGET_RE.test(t));
      if (bad) e.targets = `Not a domain, wildcard or IPv4/CIDR: ${bad}`;
    }
    const rate = Number(v.rate);
    if (!Number.isFinite(rate) || rate < 1 || rate > 100) e.rate = "Rate limit must be between 1 and 100 requests per second";
    const exp = Date.parse(v.authExpires);
    if (!v.authRef.trim() || !v.approvedBy.trim()) e.authorization = "Record the written authorization (reference and approver)";
    else if (Number.isNaN(exp) || exp <= Date.now()) e.authorization = "The authorization must have a future expiry date";
  }
  return e;
}

/**
 * Configure an engine connection. Credentials are write-only (stored in the secret store, never
 * returned). The engine always runs as a separate, unmodified service reached over its API.
 */
export function IntegrationDialog({ engine, existing, onClose }: { engine: EngineDefinition; existing?: IntegrationView | null; onClose: () => void }) {
  const session = useSession();
  const create = useCreateIntegration();
  const update = useUpdateIntegration();
  const m = existing ? update : create;
  const defaultOrg = useDefaultOrganization("integration:write", true);
  const scope = readScanScope(existing?.config);
  const [name, setName] = useState(existing?.name ?? engine.name);
  const [orgId, setOrgId] = useState<string | null>(existing ? existing.organizationId : defaultOrg);
  const [endpoint, setEndpoint] = useState(existing?.endpoint ?? "");
  const [credential, setCredential] = useState("");
  const [replaceCredential, setReplaceCredential] = useState(!existing?.hasCredential);
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [targets, setTargets] = useState(scope?.targets.join("\n") ?? "");
  const [exclusions, setExclusions] = useState(scope?.exclusions.join("\n") ?? "");
  const [rate, setRate] = useState(String(scope?.ratePerSecond || 10));
  const [authRef, setAuthRef] = useState(scope?.authorization.reference ?? "");
  const [approvedBy, setApprovedBy] = useState(scope?.authorization.approvedBy ?? "");
  const [authExpires, setAuthExpires] = useState(scope?.authorization.expiresAt ? scope.authorization.expiresAt.slice(0, 10) : "");
  const copilotSync = (existing?.config?.sync as Record<string, boolean> | undefined) ?? { customers: true, agents: true, alerts: true, cases: true };
  const [sync, setSync] = useState<Record<string, boolean>>(copilotSync);
  const [submitted, setSubmitted] = useState(false);

  const scanning = SCANNING_ENGINES.has(engine.key);
  const errors = validateIntegrationForm(engine, { name, endpoint, credential, hasStoredCredential: Boolean(existing?.hasCredential) && !replaceCredential, targets, rate, authRef, approvedBy, authExpires });
  const insecure = (() => {
    try {
      const u = new URL(endpoint);
      return u.protocol === "http:" && !/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(u.hostname);
    } catch {
      return false;
    }
  })();

  const submit = () => {
    setSubmitted(true);
    if (Object.keys(errors).length > 0) return;
    const config: Record<string, unknown> = { ...(existing?.config ?? {}) };
    if (scanning) {
      config.scope = {
        targets: lines(targets),
        exclusions: lines(exclusions),
        ratePerSecond: Number(rate),
        authorization: { reference: authRef.trim(), approvedBy: approvedBy.trim(), expiresAt: new Date(`${authExpires}T23:59:59Z`).toISOString() },
      } satisfies ScanScope;
    }
    if (engine.key === "copilot") config.sync = sync;
    const input: CreateIntegrationInput = {
      engine: engine.key,
      name: name.trim(),
      organizationId: orgId,
      endpoint: endpoint.trim() || null,
      enabled,
      ...(credential.trim() && replaceCredential ? { credential: credential.trim() } : {}),
      ...(Object.keys(config).length > 0 ? { config } : {}),
    };
    if (existing) {
      // Editing never moves a connection between organizations or engines.
      const { engine: _engine, organizationId: _org, ...patch } = input;
      update.mutate({ id: existing.id, patch }, { onSuccess: onClose });
    } else {
      create.mutate(input, { onSuccess: onClose });
    }
  };

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={`${existing ? "Configure" : "Connect"} ${engine.name}`}
      description={engine.role}
      footer={
        <>
          {m.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(m.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} loading={m.isPending}>
            {existing ? "Save" : "Connect"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <Badge tone={engine.licenseRisk === "low" ? "success" : engine.licenseRisk === "medium" ? "warning" : "danger"}>{engine.license}</Badge>
          <Badge tone="outline">{MODE_LABELS[engine.mode]}</Badge>
          {engine.powers.map((m) => (
            <Badge key={m} tone="info" size="xs">
              {moduleName(m)}
            </Badge>
          ))}
        </div>
        <p className="flex items-start gap-2 rounded border border-line bg-surface-2 p-2 text-xs text-fg-muted">
          <ShieldCheck size={13} className="mt-0.5 shrink-0 text-healthy" aria-hidden />
          {engine.licenseNotes} Bloody connects to the engine as a separate, unmodified service.
        </p>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Name" required error={submitted ? errors.name : null}>
            {(p) => <Input {...p} value={name} onChange={(e) => setName(e.target.value)} maxLength={200} />}
          </Field>
          <Field label="Scope" hint={existing ? "A connection's scope is fixed; add a new connection for another organization." : undefined}>
            {(p) =>
              existing ? (
                <Input {...p} value={existing.organizationId ? (session.organizationName(existing.organizationId) ?? "Organization") : "All organizations (MSSP-wide)"} readOnly disabled />
              ) : (
                <OrganizationSelect {...p} value={orgId} onChange={setOrgId} permission="integration:write" allowTenantWide tenantWideLabel="All organizations (MSSP-wide)" />
              )
            }
          </Field>
          <Field
            label="Endpoint"
            required={engine.mode === "network_api"}
            error={submitted ? errors.endpoint : null}
            hint={engine.mode === "network_api" ? "Base URL of the engine's API, reachable from the Bloody control plane." : "Optional: events arrive via the event stream or POST /api/v1/ingest/<adapter> with an ingestion API key."}
            className="sm:col-span-2"
          >
            {(p) => <Input {...p} value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="https://engine.internal:55000" />}
          </Field>
          {insecure ? (
            <p className="flex items-center gap-1.5 text-xs text-sev-high sm:col-span-2">
              <TriangleAlert size={12} aria-hidden /> Plain http to a non-private host sends credentials unencrypted. Prefer https.
            </p>
          ) : null}
          <Field label="Credential" error={submitted ? errors.credential : null} hint="Write-only: stored encrypted in the secret store and never shown again." className="sm:col-span-2">
            {(p) =>
              existing?.hasCredential && !replaceCredential ? (
                <div className="flex items-center gap-2">
                  <Input {...p} value="••••••••  stored" disabled readOnly />
                  <Button size="sm" onClick={() => setReplaceCredential(true)}>
                    Replace
                  </Button>
                </div>
              ) : (
                <Input {...p} type="password" autoComplete="new-password" value={credential} onChange={(e) => setCredential(e.target.value)} placeholder="API token / password" />
              )
            }
          </Field>
        </div>

        {engine.key === "copilot" ? (
          <fieldset className="rounded border border-line p-3">
            <legend className="px-1 text-xs font-semibold uppercase tracking-wide text-fg-muted">CoPilot sync</legend>
            <p className="mb-2 text-xs text-fg-muted">Import SOC hub records into Bloody's canonical model (customers → organizations, agents, alerts, cases → incidents).</p>
            <div className="grid grid-cols-2 gap-1.5">
              {(["customers", "agents", "alerts", "cases"] as const).map((k) => (
                <Checkbox key={k} label={`Sync ${k}`} checked={sync[k] !== false} onChange={(e) => setSync((s) => ({ ...s, [k]: e.target.checked }))} />
              ))}
            </div>
          </fieldset>
        ) : null}

        {scanning ? (
          <fieldset className="space-y-2 rounded border border-sev-high/40 p-3" data-testid="scan-scope">
            <legend className="px-1 text-xs font-semibold uppercase tracking-wide text-sev-high">Authorized scan scope</legend>
            <p className="text-xs text-fg-muted">Active scanning only runs against targets you are authorized to test, within this rate limit. Every scan is audited.</p>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="Authorized targets" required error={submitted ? errors.targets : null} hint="One per line: example.com, *.example.com, 203.0.113.0/24">
                {(p) => <Textarea {...p} value={targets} onChange={(e) => setTargets(e.target.value)} rows={4} className="font-mono text-xs" />}
              </Field>
              <Field label="Exclusions" hint="Never scanned, even when matched by a target">
                {(p) => <Textarea {...p} value={exclusions} onChange={(e) => setExclusions(e.target.value)} rows={4} className="font-mono text-xs" />}
              </Field>
              <Field label="Rate limit (requests / second)" required error={submitted ? errors.rate : null}>
                {(p) => <Input {...p} value={rate} inputMode="numeric" onChange={(e) => setRate(e.target.value)} />}
              </Field>
              <Field label="Authorization expires" required>
                {(p) => <Input {...p} type="date" value={authExpires} onChange={(e) => setAuthExpires(e.target.value)} />}
              </Field>
              <Field label="Authorization reference" required hint="Contract / engagement letter / ticket">
                {(p) => <Input {...p} value={authRef} onChange={(e) => setAuthRef(e.target.value)} />}
              </Field>
              <Field label="Approved by" required>
                {(p) => <Input {...p} value={approvedBy} onChange={(e) => setApprovedBy(e.target.value)} />}
              </Field>
            </div>
            {submitted && errors.authorization ? (
              <p role="alert" className="text-xs text-sev-critical">
                {errors.authorization}
              </p>
            ) : null}
          </fieldset>
        ) : null}

        <Checkbox label="Enabled" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
      </div>
    </Dialog>
  );
}
