import { CheckCircle2, Download, FileUp, Link2, ShieldAlert, ShieldCheck, Stamp } from "lucide-react";
import { useState } from "react";
import { errorMessage } from "../../api/client";
import { useAddEvidence, useAppendCustody, useDownloadEvidence } from "../../api/hooks";
import { CUSTODY_ACTIONS, type AddEvidenceInput, type CustodyAction, type EvidenceKind, type EvidenceView, type InvestigationDetail } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { CopyButton } from "../../components/CopyButton";
import { EmptyState } from "../../components/EmptyState";
import { Field, Input, Select, Textarea } from "../../components/Form";
import { Dialog } from "../../components/Overlay";
import { triggerDownload } from "../../lib/download";
import { formatDateTime, humanize } from "../../lib/format";
import { SHA256_RE, formatBytes, readFileBytes, sha256Hex, toBase64 } from "../../lib/sha256";

const EVIDENCE_KINDS: EvidenceKind[] = ["file", "memory", "disk_artifact", "log_export", "pcap", "screenshot", "note"];
const INLINE_LIMIT = 10 * 1024 * 1024;
const STORAGE_REF_RE = /^(s3|gs|az|velociraptor|arkime|file):\/\/\S+$/;

function AddEvidenceDialog({ investigationId, onClose }: { investigationId: string; onClose: () => void }) {
  const add = useAddEvidence(investigationId);
  const [mode, setMode] = useState<"upload" | "external">("upload");
  const [name, setName] = useState("");
  const [kind, setKind] = useState<EvidenceKind>("file");
  const [tags, setTags] = useState("");
  const [note, setNote] = useState("");
  const [file, setFile] = useState<{ name: string; size: number; sha256: string; base64: string } | null>(null);
  const [hashing, setHashing] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const [sha, setSha] = useState("");
  const [size, setSize] = useState("");
  const [ref, setRef] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const onFile = async (f: File | undefined) => {
    setFile(null);
    setFileError(null);
    if (!f) return;
    if (f.size > INLINE_LIMIT) {
      setFileError("Files over 10 MiB must be uploaded to object storage and registered as an external reference.");
      return;
    }
    setHashing(true);
    try {
      const bytes = await readFileBytes(f);
      setFile({ name: f.name, size: f.size, sha256: await sha256Hex(bytes), base64: toBase64(bytes) });
      if (!name) setName(f.name);
    } catch {
      setFileError("Could not read the file.");
    } finally {
      setHashing(false);
    }
  };

  const errors = {
    name: name.trim() ? null : "Name the evidence",
    file: mode === "upload" && !file ? (fileError ?? "Choose a file") : null,
    sha: mode === "external" && !SHA256_RE.test(sha.trim()) ? "SHA-256 must be 64 hex characters" : null,
    size: mode === "external" && !/^\d+$/.test(size.trim()) ? "Size in bytes" : null,
    ref: mode === "external" && !STORAGE_REF_RE.test(ref.trim()) ? "Use s3://, gs://, az://, velociraptor://, arkime:// or file://" : null,
  };

  const submit = () => {
    setSubmitted(true);
    if (Object.values(errors).some(Boolean)) return;
    const base = { name: name.trim(), kind, tags: tags.split(",").map((t) => t.trim()).filter(Boolean), ...(note.trim() ? { note: note.trim() } : {}) };
    const input: AddEvidenceInput = mode === "upload" ? { ...base, contentBase64: file!.base64 } : { ...base, sha256: sha.trim().toLowerCase(), sizeBytes: Number(size), storageRef: ref.trim() };
    add.mutate(input, { onSuccess: onClose });
  };

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title="Add evidence"
      description="The platform records the SHA-256 and starts a hash-chained chain of custody attributed to you."
      footer={
        <>
          {add.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(add.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} loading={add.isPending} disabled={hashing}>
            Add evidence
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div role="tablist" aria-label="Evidence source" className="inline-flex rounded border border-line-strong p-0.5">
          <button type="button" role="tab" aria-selected={mode === "upload"} onClick={() => setMode("upload")} className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-sm ${mode === "upload" ? "bg-primary text-white" : "text-fg-muted"}`}>
            <FileUp size={12} aria-hidden /> Upload (≤ 10 MiB)
          </button>
          <button type="button" role="tab" aria-selected={mode === "external"} onClick={() => setMode("external")} className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-sm ${mode === "external" ? "bg-primary text-white" : "text-fg-muted"}`}>
            <Link2 size={12} aria-hidden /> Register external artifact
          </button>
        </div>
        {mode === "upload" ? (
          <Field label="File" required error={submitted ? errors.file : fileError}>
            {(p) => <Input {...p} type="file" onChange={(e) => void onFile(e.target.files?.[0])} className="h-auto py-1" />}
          </Field>
        ) : null}
        {mode === "upload" && file ? (
          <p className="flex items-center gap-2 text-xs text-fg-muted">
            <ShieldCheck size={12} className="text-healthy" aria-hidden />
            {formatBytes(file.size)} · sha256 <code className="break-all font-mono">{file.sha256}</code>
          </p>
        ) : null}
        {mode === "upload" && hashing ? <p className="text-xs text-fg-muted">Hashing…</p> : null}
        {mode === "external" ? (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Field label="Storage reference" required error={submitted ? errors.ref : null} className="sm:col-span-2">
              {(p) => <Input {...p} value={ref} onChange={(e) => setRef(e.target.value)} placeholder="velociraptor://C.1234/F.ABCD/memory.raw" className="font-mono text-xs" />}
            </Field>
            <Field label="SHA-256" required error={submitted ? errors.sha : null}>
              {(p) => <Input {...p} value={sha} onChange={(e) => setSha(e.target.value)} className="font-mono text-xs" />}
            </Field>
            <Field label="Size (bytes)" required error={submitted ? errors.size : null}>
              {(p) => <Input {...p} value={size} inputMode="numeric" onChange={(e) => setSize(e.target.value)} />}
            </Field>
          </div>
        ) : null}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Name" required error={submitted ? errors.name : null}>
            {(p) => <Input {...p} value={name} onChange={(e) => setName(e.target.value)} maxLength={500} />}
          </Field>
          <Field label="Kind">
            {(p) => (
              <Select {...p} value={kind} onChange={(e) => setKind(e.target.value as EvidenceKind)}>
                {EVIDENCE_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {humanize(k)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Tags" hint="Comma-separated" className="sm:col-span-2">
            {(p) => <Input {...p} value={tags} onChange={(e) => setTags(e.target.value)} />}
          </Field>
          <Field label="Collection note" hint="How and from where it was collected" className="sm:col-span-2">
            {(p) => <Textarea {...p} value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} />}
          </Field>
        </div>
      </div>
    </Dialog>
  );
}

function CustodyDialog({ investigationId, evidence, onClose }: { investigationId: string; evidence: EvidenceView; onClose: () => void }) {
  const append = useAppendCustody(investigationId);
  const [action, setAction] = useState<CustodyAction>("analyzed");
  const [note, setNote] = useState("");
  return (
    <Dialog
      open
      onClose={onClose}
      title="Record custody event"
      description={`${evidence.name} · each entry hashes the previous one, making the chain tamper-evident.`}
      footer={
        <>
          {append.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(append.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" icon={Stamp} loading={append.isPending} onClick={() => append.mutate({ evidenceId: evidence.id, action, ...(note.trim() ? { note: note.trim() } : {}) }, { onSuccess: onClose })}>
            Record
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Action" required>
          {(p) => (
            <Select {...p} value={action} onChange={(e) => setAction(e.target.value as CustodyAction)}>
              {CUSTODY_ACTIONS.map((a) => (
                <option key={a} value={a}>
                  {humanize(a)}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Note">{(p) => <Textarea {...p} value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} />}</Field>
      </div>
    </Dialog>
  );
}

function VerificationBadge({ e }: { e: EvidenceView }) {
  if (!e.custodyVerification) return <Badge size="xs">Unverified</Badge>;
  return e.custodyVerification.valid ? (
    <Badge size="xs" tone="success" icon={ShieldCheck}>
      Chain intact
    </Badge>
  ) : (
    <Badge size="xs" tone="danger" icon={ShieldAlert}>
      Chain broken at #{(e.custodyVerification.brokenAt ?? 0) + 1}
    </Badge>
  );
}

/** Evidence locker for one investigation: sha256, size, storage, download (audited), custody. */
export function EvidencePanel({ investigation }: { investigation: InvestigationDetail }) {
  const session = useSession();
  const canWrite = session.can("investigation:write", investigation.organizationId) && investigation.status !== "closed";
  const download = useDownloadEvidence(investigation.id);
  const [adding, setAdding] = useState(false);
  const [custodyFor, setCustodyFor] = useState<EvidenceView | null>(null);
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-sm text-fg-muted">{investigation.evidence.length} item(s) · downloads are appended to the chain of custody.</p>
        {canWrite ? (
          <Button size="sm" variant="primary" icon={FileUp} onClick={() => setAdding(true)}>
            Add evidence
          </Button>
        ) : null}
      </div>
      {investigation.evidence.length === 0 ? (
        <EmptyState compact icon={FileUp} title="No evidence collected yet" description="Upload artifacts or register collections from Velociraptor, Arkime or object storage." />
      ) : (
        <ul className="divide-y divide-line rounded border border-line" data-testid="evidence-list">
          {investigation.evidence.map((e) => (
            <li key={e.id} className="space-y-1 px-3 py-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-heading">{e.name}</span>
                <Badge size="xs" tone="outline">
                  {humanize(e.kind)}
                </Badge>
                <span className="text-xs text-fg-subtle">{formatBytes(e.sizeBytes)}</span>
                <VerificationBadge e={e} />
                {e.tags.map((t) => (
                  <Badge key={t} size="xs">
                    {t}
                  </Badge>
                ))}
                <span className="ml-auto flex gap-1">
                  {e.inline !== false ? (
                    <Button
                      size="xs"
                      icon={Download}
                      loading={download.isPending && download.variables?.evidenceId === e.id}
                      onClick={() => download.mutate({ evidenceId: e.id }, { onSuccess: (r) => triggerDownload(r.blob, r.filename ?? e.name) })}
                    >
                      Download
                    </Button>
                  ) : null}
                  {canWrite ? (
                    <Button size="xs" icon={Stamp} onClick={() => setCustodyFor(e)}>
                      Custody
                    </Button>
                  ) : null}
                </span>
              </div>
              <div className="flex items-center gap-1 text-xs text-fg-muted">
                sha256 <code className="break-all font-mono">{e.sha256}</code>
                <CopyButton value={e.sha256} label="Copy SHA-256" />
              </div>
              <div className="text-2xs text-fg-subtle">
                {e.storageRef} · collected by {e.collectedBy} · {formatDateTime(e.createdAt)}
              </div>
            </li>
          ))}
        </ul>
      )}
      {download.isError ? (
        <p role="alert" className="text-sm text-sev-critical">
          {errorMessage(download.error)}
        </p>
      ) : null}
      {adding ? <AddEvidenceDialog investigationId={investigation.id} onClose={() => setAdding(false)} /> : null}
      {custodyFor ? <CustodyDialog investigationId={investigation.id} evidence={custodyFor} onClose={() => setCustodyFor(null)} /> : null}
    </div>
  );
}

/** Chain of custody: every evidence item's append-only, hash-chained log. */
export function CustodyPanel({ investigation, actorName }: { investigation: InvestigationDetail; actorName: (a: string | null) => string }) {
  if (investigation.evidence.length === 0) return <EmptyState compact icon={Stamp} title="No chain of custody yet" description="Custody starts when the first evidence item is collected." />;
  return (
    <div className="space-y-4" data-testid="custody-panel">
      {investigation.evidence.map((e) => (
        <section key={e.id} className="rounded border border-line">
          <header className="flex flex-wrap items-center gap-2 border-b border-line bg-surface-2 px-3 py-2">
            <span className="font-medium">{e.name}</span>
            <VerificationBadge e={e} />
            <code className="ml-auto truncate font-mono text-2xs text-fg-subtle" title={e.sha256}>
              {e.sha256}
            </code>
          </header>
          <ol className="divide-y divide-line">
            {e.custody.map((c, i) => {
              const broken = e.custodyVerification && !e.custodyVerification.valid && e.custodyVerification.brokenAt !== null && i >= e.custodyVerification.brokenAt;
              return (
                <li key={`${c.hash}-${i}`} className="grid grid-cols-[24px_1fr] gap-2 px-3 py-1.5 text-sm">
                  {broken ? <ShieldAlert size={14} className="mt-0.5 text-sev-critical" aria-label="Unverified link" /> : <CheckCircle2 size={14} className="mt-0.5 text-healthy" aria-label="Verified link" />}
                  <div className="min-w-0">
                    <div className="flex flex-wrap gap-x-2">
                      <span className="font-mono text-2xs text-fg-subtle">#{i + 1}</span>
                      <span className="font-medium">{humanize(c.action)}</span>
                      <span className="text-fg-muted">{actorName(c.actor)}</span>
                      <span className="font-mono text-2xs text-fg-subtle">{formatDateTime(c.at)}</span>
                    </div>
                    {c.note ? <p className="text-xs text-fg-muted">{c.note}</p> : null}
                    <code className="block truncate font-mono text-2xs text-fg-subtle" title={c.hash}>
                      {c.hash}
                    </code>
                  </div>
                </li>
              );
            })}
          </ol>
        </section>
      ))}
    </div>
  );
}
