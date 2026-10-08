import { Severity } from "@bloody/contracts";
import { CheckCircle2, FlaskConical, History, Plus, Save, Sigma, Trash2, TriangleAlert, Undo2, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { errorMessage } from "../../api/client";
import { useDeleteDetection, useDetections, useDetectionVersions, useRollbackDetection, useSaveDetection, useTestDetection } from "../../api/hooks";
import type { DetectionKind, DetectionRule, UpsertDetectionInput } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, SeverityBadge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { CodeEditor } from "../../components/CodeEditor";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { Checkbox, Field, Input, Select, Textarea } from "../../components/Form";
import { OrganizationSelect, useDefaultOrganization } from "../../components/OrganizationSelect";
import { Drawer } from "../../components/Overlay";
import { RelativeTime } from "../../components/RelativeTime";
import { formatInteger, humanize } from "../../lib/format";
import { SIGMA_TEMPLATE, lintSigma, sigmaLevel, sigmaTechniques, sigmaTitle } from "../../lib/sigma";
import { EventsTable } from "../events/EventsTable";

const KINDS: DetectionKind[] = ["sigma", "threshold", "sequence", "ioc", "yara", "suricata", "custom"];
const KIND_LABEL: Record<DetectionKind, string> = { sigma: "Sigma", threshold: "Threshold", sequence: "Sequence", ioc: "IOC match", yara: "YARA", suricata: "Suricata", custom: "Custom" };
const LOOKBACKS = [1, 24, 72, 168];

interface Draft {
  name: string;
  description: string;
  kind: DetectionKind;
  severity: Severity;
  enabled: boolean;
  source: string;
  organizationId: string | null;
  tags: string;
}

function draftFrom(rule: DetectionRule | null, defaultOrg: string | null): Draft {
  if (!rule) return { name: sigmaTitle(SIGMA_TEMPLATE) ?? "", description: "", kind: "sigma", severity: sigmaLevel(SIGMA_TEMPLATE) ?? "high", enabled: false, source: SIGMA_TEMPLATE, organizationId: defaultOrg, tags: "" };
  return { name: rule.name, description: rule.description ?? "", kind: rule.kind, severity: rule.severity, enabled: rule.enabled, source: rule.source, organizationId: rule.organizationId, tags: (rule.tags ?? []).join(", ") };
}

/**
 * Rule editor: Sigma YAML (or the JSON definition of threshold / sequence / IOC rules) with
 * live structural lint, versioned save, and "Test" against recent events before enabling.
 */
function RuleEditor({ rule, onClose }: { rule: DetectionRule | null; onClose: () => void }) {
  const session = useSession();
  const defaultOrg = useDefaultOrganization("detection:write", true);
  const save = useSaveDetection();
  const test = useTestDetection();
  const rollback = useRollbackDetection();
  const remove = useDeleteDetection();
  const [draft, setDraft] = useState<Draft>(() => draftFrom(rule, defaultOrg));
  const [savedRule, setSavedRule] = useState<DetectionRule | null>(rule);
  const versions = useDetectionVersions(savedRule && !savedRule.builtin ? savedRule.id : savedRule?.overridesBuiltin ? savedRule.id : null);
  const [lookback, setLookback] = useState(24);
  const [submitted, setSubmitted] = useState(false);
  const readOnly = !session.can("detection:write", savedRule ? savedRule.organizationId : draft.organizationId);
  const lint = useMemo(() => (draft.kind === "sigma" ? lintSigma(draft.source) : jsonLint(draft.source)), [draft.kind, draft.source]);
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setDraft((d) => ({ ...d, [k]: v }));
  const errors = { name: draft.name.trim().length >= 3 ? null : "Name the rule (min. 3 characters)" };
  const dirty = !savedRule || JSON.stringify(draftFrom(savedRule, defaultOrg)) !== JSON.stringify(draft);

  const input = (): UpsertDetectionInput => ({
    name: draft.name.trim(),
    description: draft.description.trim() || null,
    kind: draft.kind,
    severity: draft.severity,
    enabled: draft.enabled,
    source: draft.source,
    organizationId: draft.organizationId,
    tags: draft.tags.split(",").map((t) => t.trim()).filter(Boolean),
  });

  const doSave = () => {
    setSubmitted(true);
    if (errors.name || lint.errors.length > 0 || readOnly) return;
    save.mutate({ ...(savedRule ? { id: savedRule.id } : {}), input: input() }, { onSuccess: (r) => setSavedRule(r) });
  };
  // Drafts are tested without saving (POST /detections/test); saved rules test the editor's source.
  const doTest = () => {
    if (lint.errors.length > 0) return;
    test.mutate({ ...(savedRule ? { id: savedRule.id } : {}), input: { source: draft.source, kind: draft.kind, lookbackHours: lookback } });
  };

  const techniques = draft.kind === "sigma" ? sigmaTechniques(draft.source) : [];
  const title = savedRule ? `${savedRule.name}${savedRule.builtin && !savedRule.overridesBuiltin ? " (built-in)" : savedRule.overridesBuiltin ? " (customized built-in)" : ""}` : "New detection rule";

  return (
    <Drawer
      open
      onClose={onClose}
      width="xl"
      title={title}
      subtitle={savedRule ? `v${savedRule.version} · ${KIND_LABEL[savedRule.kind] ?? savedRule.kind}${savedRule.updatedAt ? ` · updated ${new Date(savedRule.updatedAt).toLocaleString()}` : ""}` : "Detection-as-code: validated, versioned and tested before it is enabled."}
      footer={
        <div className="flex flex-wrap items-center gap-2">
          {save.isError || remove.isError || rollback.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(save.error ?? remove.error ?? rollback.error)}
            </span>
          ) : save.isSuccess && !dirty ? (
            <span role="status" className="mr-auto text-sm text-healthy">
              Saved as version {savedRule?.version ?? "—"}.
            </span>
          ) : savedRule?.builtin && !savedRule.overridesBuiltin ? (
            <span className="mr-auto text-xs text-fg-muted">Built-in rule: saving creates your override; delete the override to return to the shipped version.</span>
          ) : (
            <span className="mr-auto text-xs text-fg-muted">Saving creates a new version; earlier versions stay available for rollback.</span>
          )}
          {savedRule && !readOnly && (!savedRule.builtin || savedRule.overridesBuiltin) ? (
            <Button variant="ghost" icon={savedRule.overridesBuiltin ? Undo2 : Trash2} loading={remove.isPending} onClick={() => remove.mutate(savedRule.id, { onSuccess: onClose })}>
              {savedRule.overridesBuiltin ? "Revert to built-in" : "Delete rule"}
            </Button>
          ) : null}
          <Button icon={FlaskConical} onClick={doTest} loading={test.isPending} disabled={lint.errors.length > 0}>
            Test
          </Button>
          {!readOnly ? (
            <Button variant="primary" icon={Save} onClick={doSave} loading={save.isPending} disabled={!dirty}>
              Save
            </Button>
          ) : null}
        </div>
      }
    >
      <div className="space-y-3 p-4">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
          <Field label="Name" required error={submitted ? errors.name : null} className="md:col-span-2">
            {(p) => <Input {...p} value={draft.name} onChange={(e) => set("name", e.target.value)} maxLength={200} readOnly={readOnly} />}
          </Field>
          <Field label="Kind">
            {(p) => (
              <Select {...p} value={draft.kind} onChange={(e) => set("kind", e.target.value as DetectionKind)} disabled={readOnly || Boolean(savedRule)}>
                {KINDS.map((k) => (
                  <option key={k} value={k}>
                    {KIND_LABEL[k]}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Severity">
            {(p) => (
              <Select {...p} value={draft.severity} onChange={(e) => set("severity", e.target.value as Severity)} disabled={readOnly}>
                {Severity.options.map((s) => (
                  <option key={s} value={s}>
                    {humanize(s)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Scope" className="md:col-span-2">
            {(p) => <OrganizationSelect {...p} value={draft.organizationId} onChange={(v) => set("organizationId", v)} permission="detection:write" allowTenantWide />}
          </Field>
          <Field label="Tags" hint="Comma-separated" className="md:col-span-2">
            {(p) => <Input {...p} value={draft.tags} onChange={(e) => set("tags", e.target.value)} readOnly={readOnly} />}
          </Field>
          <Field label="Description" className="md:col-span-4">
            {(p) => <Textarea {...p} value={draft.description} onChange={(e) => set("description", e.target.value)} maxLength={4000} className="min-h-[48px]" readOnly={readOnly} />}
          </Field>
        </div>
        <Field label={draft.kind === "sigma" ? "Sigma rule (YAML)" : "Rule definition (JSON)"} hint={draft.kind === "sigma" ? "Standard Sigma field names (Image, CommandLine, …) or canonical event paths (process.name). Ctrl+Enter tests the rule." : undefined}>
          {(p) => (
            <CodeEditor
              id={p.id}
              value={draft.source}
              onChange={(v) => {
                set("source", v);
                if (!savedRule && draft.kind === "sigma") {
                  const t = sigmaTitle(v);
                  const l = sigmaLevel(v);
                  setDraft((d) => ({ ...d, source: v, ...(t && d.name === (sigmaTitle(d.source) ?? "") ? { name: t } : {}), ...(l ? { severity: l } : {}) }));
                }
              }}
              onSubmit={doTest}
              readOnly={readOnly}
              ariaLabel={draft.kind === "sigma" ? "Sigma YAML" : "Rule definition"}
              invalid={lint.errors.length > 0}
              rows={20}
            />
          )}
        </Field>
        <div className="space-y-1" aria-live="polite" data-testid="rule-lint">
          {lint.errors.map((e) => (
            <p key={e} className="flex items-center gap-1.5 text-xs text-sev-critical">
              <XCircle size={12} aria-hidden /> {e}
            </p>
          ))}
          {lint.warnings.map((w) => (
            <p key={w} className="flex items-center gap-1.5 text-xs text-sev-high">
              <TriangleAlert size={12} aria-hidden /> {w}
            </p>
          ))}
          {lint.errors.length === 0 ? (
            <p className="flex items-center gap-1.5 text-xs text-healthy">
              <CheckCircle2 size={12} aria-hidden /> Structure looks valid — the server compiles and validates it on save and test.
            </p>
          ) : null}
          {techniques.length > 0 ? (
            <p className="flex flex-wrap items-center gap-1 text-xs text-fg-muted">
              ATT&CK:{" "}
              {techniques.map((t) => (
                <Badge key={t} size="xs" tone="outline">
                  {t}
                </Badge>
              ))}
            </p>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-3 rounded border border-line p-2">
          <Checkbox label="Enabled" checked={draft.enabled} onChange={(e) => set("enabled", e.target.checked)} disabled={readOnly} />
          <label className="flex items-center gap-1.5 text-sm text-fg-muted">
            Test against the last
            <Select value={lookback} onChange={(e) => setLookback(Number(e.target.value))} className="h-7 w-28" aria-label="Test lookback">
              {LOOKBACKS.map((h) => (
                <option key={h} value={h}>
                  {h < 24 ? `${h} hour` : `${h / 24} day${h === 24 ? "" : "s"}`}
                </option>
              ))}
            </Select>
          </label>
        </div>
        {test.isError ? (
          <p role="alert" className="text-sm text-sev-critical">
            {errorMessage(test.error)}
          </p>
        ) : null}
        {test.data ? (
          <section className="space-y-2 rounded border border-line p-3" data-testid="rule-test-result" aria-label="Test result">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              {test.data.valid ? (
                <Badge tone="success" icon={CheckCircle2}>
                  Compiles
                </Badge>
              ) : (
                <Badge tone="danger" icon={XCircle}>
                  Invalid
                </Badge>
              )}
              <span className="font-medium text-fg">
                {formatInteger(test.data.matched)} match{test.data.matched === 1 ? "" : "es"}
              </span>
              {test.data.scanned !== null && test.data.scanned !== undefined ? <span className="text-fg-muted">in {formatInteger(test.data.scanned)} events scanned</span> : null}
              {test.data.valid && test.data.matched === 0 ? <span className="text-xs text-fg-subtle">No hits in the window — check the logsource and field names, or widen the window.</span> : null}
            </div>
            {test.data.errors.map((e) => (
              <p key={e} className="text-xs text-sev-critical">
                {e}
              </p>
            ))}
            {test.data.warnings.map((w) => (
              <p key={w} className="text-xs text-sev-high">
                {w}
              </p>
            ))}
            {test.data.matches.length > 0 ? (
              <ul className="space-y-1 text-sm" aria-label="Would-be alerts">
                {test.data.matches.slice(0, 10).map((m) => (
                  <li key={m.id} className="flex items-start gap-2">
                    {m.severity ? <SeverityBadge severity={m.severity} size="xs" /> : null}
                    <span className="min-w-0 flex-1">
                      <span className="font-medium">{m.title}</span>
                      {m.explanation ? <span className="block text-xs text-fg-muted">{m.explanation}</span> : null}
                    </span>
                    <span className="text-2xs text-fg-subtle">{m.eventIds.length} event(s)</span>
                  </li>
                ))}
              </ul>
            ) : null}
            {test.data.truncated ? <p className="text-2xs text-fg-subtle">Replay limited to the most recent events in the window.</p> : null}
            {test.data.events.length > 0 ? <EventsTable rows={test.data.events} exportFileName="detection-test-matches" /> : null}
          </section>
        ) : null}
        {versions.data && versions.data.length > 1 ? (
          <section className="rounded border border-line" aria-label="Versions">
            <h3 className="border-b border-line px-3 py-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">
              <History size={12} className="mr-1 inline" aria-hidden />
              Version history
            </h3>
            <ul className="divide-y divide-line">
              {versions.data.map((v) => (
                <li key={v.version} className="flex flex-wrap items-center gap-2 px-3 py-1.5 text-sm">
                  <span className="font-mono text-xs">v{v.version}</span>
                  <span className="min-w-0 flex-1 truncate text-fg-muted">{v.comment ?? "—"}</span>
                  <RelativeTime value={v.createdAt} className="text-xs text-fg-subtle" />
                  {savedRule && v.version !== savedRule.version && !readOnly ? (
                    <Button size="xs" icon={Undo2} loading={rollback.isPending && rollback.variables?.version === v.version} onClick={() => rollback.mutate({ id: savedRule.id, version: v.version }, { onSuccess: (r) => { setSavedRule(r); setDraft(draftFrom(r, defaultOrg)); } })}>
                      Roll back
                    </Button>
                  ) : v.version === savedRule?.version ? (
                    <Badge size="xs" tone="info">current</Badge>
                  ) : null}
                </li>
              ))}
            </ul>
          </section>
        ) : null}
      </div>
    </Drawer>
  );
}

function jsonLint(source: string): { errors: string[]; warnings: string[] } {
  if (!source.trim()) return { errors: ["The rule definition is empty"], warnings: [] };
  try {
    const v: unknown = JSON.parse(source);
    return typeof v === "object" && v !== null && !Array.isArray(v) ? { errors: [], warnings: [] } : { errors: ["The definition must be a JSON object"], warnings: [] };
  } catch (e) {
    return { errors: [`Invalid JSON: ${(e as Error).message}`], warnings: [] };
  }
}

/** Detection rules: list with kind, severity, enabled, version, matches, plus the editor. */
export function DetectionRulesView({ kinds, initialId = null }: { kinds?: DetectionKind[]; initialId?: string | null }) {
  const session = useSession();
  const rules = useDetections();
  const save = useSaveDetection();
  const [editing, setEditing] = useState<DetectionRule | "new" | null>(null);
  const [initialDismissed, setInitialDismissed] = useState(false);
  const rows = useMemo(() => rules.data?.items.filter((r) => !kinds || kinds.includes(r.kind)), [rules.data, kinds]);
  const initial = initialId && !initialDismissed ? rows?.find((r) => r.id === initialId) : undefined;
  const open = editing ?? initial ?? null;
  const canWrite = session.canAnywhere("detection:write");

  const columns: DataTableColumn<DetectionRule>[] = [
    { id: "name", header: "Rule", accessor: (r) => r.name, hideable: false, cell: (r) => <span><span className="block font-medium text-heading">{r.name}</span>{r.description ? <span className="block max-w-[420px] truncate text-xs text-fg-subtle">{r.description}</span> : null}</span> },
    { id: "kind", header: "Kind", accessor: (r) => KIND_LABEL[r.kind] ?? r.kind, filter: { kind: "select", options: KINDS.map((k) => ({ value: KIND_LABEL[k], label: KIND_LABEL[k] })) } },
    { id: "severity", header: "Severity", accessor: (r) => Severity.options.indexOf(r.severity), cell: (r) => <SeverityBadge severity={r.severity} size="xs" /> },
    { id: "attack", header: "ATT&CK", accessor: (r) => r.attack.map((t) => t.id).join(", "), cell: (r) => <span className="font-mono text-xs">{r.attack.map((t) => t.id).join(", ") || "—"}</span> },
    { id: "scope", header: "Scope", accessor: (r) => (r.builtin ? (r.overridesBuiltin ? "Built-in (customized)" : "Built-in") : r.organizationId ? (session.organizationName(r.organizationId) ?? "Organization") : "Tenant-wide") },
    { id: "version", header: "Version", accessor: (r) => r.version, align: "right", cell: (r) => `v${r.version}` },
    { id: "matches", header: "Matches 24h", accessor: (r) => r.matches24h ?? null, align: "right" },
    { id: "matches7d", header: "Matches 7d", accessor: (r) => r.matches7d ?? null, align: "right", defaultHidden: true },
    { id: "fp", header: "FP rate", accessor: (r) => r.falsePositiveRate ?? null, align: "right", cell: (r) => (r.falsePositiveRate === null || r.falsePositiveRate === undefined ? "—" : `${Math.round(r.falsePositiveRate * 100)}%`), defaultHidden: true },
    { id: "last", header: "Last match", accessor: (r) => (r.lastMatchedAt ? new Date(r.lastMatchedAt) : null), cell: (r) => <RelativeTime value={r.lastMatchedAt ?? null} /> },
    {
      id: "enabled",
      header: "Enabled",
      accessor: (r) => (r.enabled ? "on" : "off"),
      filter: { kind: "select", options: [{ value: "on", label: "Enabled" }, { value: "off", label: "Disabled" }] },
      cell: (r) =>
        canWrite && session.can("detection:write", r.organizationId) ? (
          <span onClick={(e) => e.stopPropagation()}>
            <Checkbox
              label={<span className="sr-only">Enable {r.name}</span>}
              checked={r.enabled}
              disabled={save.isPending}
              onChange={(e) => save.mutate({ id: r.id, input: { name: r.name, description: r.description, kind: r.kind, severity: r.severity, enabled: e.target.checked, source: r.source, organizationId: r.organizationId, tags: r.tags ?? [] } })}
            />
          </span>
        ) : r.enabled ? (
          <Badge size="xs" tone="success">On</Badge>
        ) : (
          <Badge size="xs">Off</Badge>
        ),
    },
  ];

  return (
    <>
      {save.isError && !open ? (
        <p role="alert" className="mb-2 text-sm text-sev-critical">
          {errorMessage(save.error)}
        </p>
      ) : null}
      <DataTable
        caption="Detection rules"
        columns={columns}
        rows={rows}
        getRowId={(r) => r.id}
        loading={rules.isPending}
        error={rules.error}
        onRetry={() => void rules.refetch()}
        onRowClick={(r) => setEditing(r)}
        initialState={{ sort: { columnId: "severity", direction: "desc" } }}
        savedViewsKey="detection-rules"
        exportFileName="bloody-detection-rules"
        toolbar={
          canWrite ? (
            <Button size="sm" variant="primary" icon={Plus} onClick={() => setEditing("new")}>
              New rule
            </Button>
          ) : null
        }
        emptyState={
          <ConnectEngineEmptyState
            compact
            icon={Sigma}
            title="No detection rules yet"
            description="Write Sigma, threshold or sequence rules, or import community Sigma content (DRL-1.1, attribution kept in metadata)."
            engines={["sigma"]}
            extraAction={canWrite ? <Button size="sm" icon={Plus} onClick={() => setEditing("new")}>New rule</Button> : undefined}
          />
        }
      />
      {open ? (
        <RuleEditor
          rule={open === "new" ? null : open}
          onClose={() => {
            setEditing(null);
            setInitialDismissed(true);
          }}
          key={open === "new" ? "new" : open.id}
        />
      ) : null}
    </>
  );
}
