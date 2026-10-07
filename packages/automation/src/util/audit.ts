/**
 * Audit hook. The API implements this by writing `audit_log` rows; automation never writes
 * to the database itself. Every approval decision, denied decision, playbook execution and
 * dead-letter redrive is reported here.
 */
export interface AuditEntry {
  tenantId: string;
  organizationId: string | null;
  actor: { kind: "user" | "service" | "system" | "playbook" | "ai"; id: string };
  action: string;
  target: { kind: string; id: string };
  outcome: "success" | "failure" | "denied";
  at: string;
  details?: Record<string, unknown>;
}

export interface AuditSink {
  record(entry: AuditEntry): Promise<void> | void;
}

/** Sink that drops entries — only for tests or tools that do not need an audit trail. */
export const nullAuditSink: AuditSink = { record: () => undefined };

/** Records into memory; handy for tests and the single-process dev deployment. */
export class MemoryAuditSink implements AuditSink {
  readonly entries: AuditEntry[] = [];

  record(entry: AuditEntry): void {
    this.entries.push(entry);
  }
}

/** Write an audit entry without ever letting an audit failure break the business operation. */
export async function safeAudit(sink: AuditSink | undefined, entry: AuditEntry): Promise<void> {
  if (!sink) return;
  try {
    await sink.record(entry);
  } catch {
    // Audit sinks are expected to be reliable (DB); an exception here must not crash a
    // half-finished automation. The API's sink surfaces its own errors to metrics/logs.
  }
}
