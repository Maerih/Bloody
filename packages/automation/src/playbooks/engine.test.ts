import type { Playbook } from "@bloody/contracts";
import { describe, expect, it } from "vitest";
import { ApprovalGate } from "../approvals/gate.js";
import { InMemoryApprovalStore } from "../approvals/types.js";
import { MemoryAuditSink } from "../util/audit.js";
import { FakeClock, ORG_A, ORG_B, principal, sequentialIds, TENANT } from "../test-support/fixtures.js";
import { PlaybookEngine } from "./engine.js";
import { InMemoryPlaybookRepository, type PlaybookDraft } from "./repository.js";
import { ActionExecutionError, InMemoryExecutionStore, type ActionExecutionRequest, type ActionExecutor } from "./types.js";

class FakeExecutor implements ActionExecutor {
  readonly calls: ActionExecutionRequest[] = [];
  private readonly failures = new Map<string, (ActionExecutionError | Error)[]>();
  private readonly executed = new Set<string>();

  failNext(action: string, ...errors: (ActionExecutionError | Error)[]): void {
    this.failures.set(action, errors);
  }

  async execute(req: ActionExecutionRequest) {
    this.calls.push(req);
    const queue = this.failures.get(req.action);
    if (queue && queue.length > 0) throw queue.shift()!;
    const duplicate = this.executed.has(req.idempotencyKey);
    this.executed.add(req.idempotencyKey);
    return { output: { action: req.action, duplicate }, externalRef: `ra-${this.calls.length}` };
  }
}

function setup() {
  const clock = new FakeClock();
  const ids = sequentialIds("ffffffff");
  const audit = new MemoryAuditSink();
  const repo = new InMemoryPlaybookRepository({ clock, ids: sequentialIds("eeeeeeee") });
  const executions = new InMemoryExecutionStore();
  const executor = new FakeExecutor();
  const approvals = new ApprovalGate({ store: new InMemoryApprovalStore(), clock, ids: sequentialIds("dddddddd"), audit });
  const delays: number[] = [];
  const engine = new PlaybookEngine({
    playbooks: repo,
    executions,
    executor,
    approvals,
    clock,
    ids,
    audit,
    random: () => 0.5,
    sleep: async (ms) => {
      delays.push(ms);
    },
    retry: { maxAttempts: 3, baseDelayMs: 1000, factor: 2, maxDelayMs: 10_000 },
  });
  approvals.onDecision((r) => engine.resumeFromApproval(r).then(() => undefined));
  return { clock, repo, executions, executor, approvals, engine, audit, delays };
}

const containment: PlaybookDraft = {
  organizationId: null,
  name: "Ransomware containment",
  description: "Contain ransomware precursors",
  enabled: true,
  trigger: { on: "incident.created" },
  conditions: [
    { field: "incident.severity", op: "gte", value: "high" },
    { field: "incident.attack", op: "contains", value: "T1486" },
  ],
  steps: [
    { id: "case", action: "create_case", parameters: { title: "Incident #{{incident.number}}" }, requireApproval: false, continueOnError: false },
    { id: "isolate", action: "isolate_endpoint", parameters: { assetId: "{{incident.assetId}}" }, requireApproval: false, continueOnError: false },
    { id: "notify", action: "notify_analyst", parameters: {}, requireApproval: false, continueOnError: false },
  ],
};

function incidentEvent(overrides: Record<string, unknown> = {}, organizationId = ORG_A) {
  return {
    tenantId: TENANT,
    organizationId,
    type: "incident.created" as const,
    subject: { incident: { id: "inc-1", number: 7, severity: "critical", attack: ["T1059", "T1486"], assetId: "asset-9", ...overrides } },
    subjectRef: { kind: "incident", id: "inc-1" },
    occurredAt: "2026-10-07T11:59:00.000Z",
  };
}

describe("PlaybookEngine", () => {
  it("runs low-risk steps and stops at the approval gate for high-risk ones", async () => {
    const { repo, engine, executor } = setup();
    await repo.create(TENANT, containment, "engineer");
    const res = await engine.handleEvent(incidentEvent());
    expect(res.matches).toHaveLength(1);
    const exec = res.matches[0]!.execution!;
    expect(exec.status).toBe("waiting_approval");
    expect(exec.steps.map((s) => s.status)).toEqual(["succeeded", "pending_approval", "pending"]);
    expect(executor.calls.map((c) => c.action)).toEqual(["create_case"]);
    expect(executor.calls[0]!.parameters).toEqual({ title: "Incident #7" });
    const waiting = exec.log.find((l) => l.status === "pending_approval")!;
    expect(waiting.message).toMatch(/high-risk/);
    expect(waiting.approvalId).toBeTruthy();
  });

  it("resumes after approval by another analyst and completes in order", async () => {
    const { repo, engine, executor, approvals } = setup();
    await repo.create(TENANT, containment, "engineer");
    const exec = (await engine.handleEvent(incidentEvent())).matches[0]!.execution!;
    const approvalId = exec.steps[1]!.approvalId!;
    const pending = await approvals.get(TENANT, approvalId);
    expect(pending!.subject).toMatchObject({ playbookId: exec.playbookId, executionId: exec.id, stepId: "isolate", incidentId: "inc-1" });
    expect(pending!.parameters).toEqual({ assetId: "asset-9" });
    await approvals.approve(TENANT, approvalId, principal("bob", "incident_responder"));
    const final = (await engine.getExecution(TENANT, exec.id))!;
    expect(final.status).toBe("succeeded");
    expect(final.steps.map((s) => s.status)).toEqual(["succeeded", "succeeded", "succeeded"]);
    expect(executor.calls.map((c) => c.action)).toEqual(["create_case", "isolate_endpoint", "notify_analyst"]);
    expect(executor.calls[1]!.approval).toEqual({ id: approvalId, approvedBy: ["bob"] });
    const log = final.log.map((l) => `${l.stepId ?? "-"}:${l.status}`);
    expect(log).toEqual(["-:info", "case:succeeded", "isolate:pending_approval", "isolate:approved", "isolate:succeeded", "notify:succeeded", "-:info"]);
    for (const entry of final.log) {
      expect(entry.startedAt).toBeTruthy();
    }
  });

  it("stops on rejection unless the step continues on error", async () => {
    const { repo, engine, approvals, executor } = setup();
    await repo.create(TENANT, containment, "engineer");
    const exec = (await engine.handleEvent(incidentEvent())).matches[0]!.execution!;
    await approvals.reject(TENANT, exec.steps[1]!.approvalId!, principal("bob", "incident_responder"), "benign admin tool");
    const final = (await engine.getExecution(TENANT, exec.id))!;
    expect(final.status).toBe("rejected");
    expect(final.steps.map((s) => s.status)).toEqual(["succeeded", "rejected", "skipped"]);
    expect(executor.calls.map((c) => c.action)).toEqual(["create_case"]);

    const { repo: repo2, engine: engine2, approvals: approvals2 } = setup();
    await repo2.create(TENANT, { ...containment, steps: containment.steps.map((s) => (s.id === "isolate" ? { ...s, continueOnError: true } : s)) }, "engineer");
    const exec2 = (await engine2.handleEvent(incidentEvent())).matches[0]!.execution!;
    await approvals2.reject(TENANT, exec2.steps[1]!.approvalId!, principal("bob", "incident_responder"));
    const final2 = (await engine2.getExecution(TENANT, exec2.id))!;
    expect(final2.status).toBe("partially_succeeded");
    expect(final2.steps.map((s) => s.status)).toEqual(["succeeded", "rejected", "succeeded"]);
  });

  it("honours requireApproval on low-risk steps", async () => {
    const { repo, engine, executor } = setup();
    await repo.create(TENANT, { ...containment, steps: [{ id: "mail", action: "send_email", parameters: {}, requireApproval: true, continueOnError: false }] }, "eng");
    const exec = (await engine.handleEvent(incidentEvent())).matches[0]!.execution!;
    expect(exec.status).toBe("waiting_approval");
    expect(executor.calls).toHaveLength(0);
    expect(exec.log.at(-1)!.message).toMatch(/configured to require approval/);
  });

  it("retries retryable failures with exponential backoff, then fails", async () => {
    const { repo, engine, executor, delays } = setup();
    await repo.create(TENANT, { ...containment, steps: [{ id: "case", action: "create_case", parameters: {}, requireApproval: false, continueOnError: false }, { id: "notify", action: "notify_analyst", parameters: {}, requireApproval: false, continueOnError: false }] }, "eng");
    executor.failNext("create_case", new Error("ECONNRESET"), new ActionExecutionError("upstream_503", "ticketing down", true));
    const exec = (await engine.handleEvent(incidentEvent())).matches[0]!.execution!;
    expect(exec.status).toBe("succeeded");
    expect(exec.steps[0]!.attempts).toBe(3);
    expect(delays).toEqual([750, 1500]);
    const keys = executor.calls.filter((c) => c.action === "create_case").map((c) => c.idempotencyKey);
    expect(new Set(keys).size).toBe(1);
    expect(executor.calls.filter((c) => c.action === "create_case").map((c) => c.attempt)).toEqual([1, 2, 3]);

    const s2 = setup();
    await s2.repo.create(TENANT, { ...containment, steps: [{ id: "case", action: "create_case", parameters: {}, requireApproval: false, continueOnError: false }, { id: "notify", action: "notify_analyst", parameters: {}, requireApproval: false, continueOnError: false }] }, "eng");
    s2.executor.failNext("create_case", new ActionExecutionError("bad_request", "invalid parameters", false));
    const failed = (await s2.engine.handleEvent(incidentEvent())).matches[0]!.execution!;
    expect(failed.status).toBe("failed");
    expect(failed.steps.map((s) => s.status)).toEqual(["failed", "skipped"]);
    expect(failed.log.find((l) => l.status === "failed")!.error).toMatchObject({ code: "bad_request", retryable: false });
    expect(s2.delays).toEqual([]);
  });

  it("continues past a failed step with continueOnError", async () => {
    const { repo, engine, executor } = setup();
    await repo.create(TENANT, { ...containment, steps: [{ id: "case", action: "create_case", parameters: {}, requireApproval: false, continueOnError: true }, { id: "notify", action: "notify_analyst", parameters: {}, requireApproval: false, continueOnError: false }] }, "eng");
    executor.failNext("create_case", new ActionExecutionError("x", "nope", false));
    const exec = (await engine.handleEvent(incidentEvent())).matches[0]!.execution!;
    expect(exec.status).toBe("partially_succeeded");
    expect(exec.steps.map((s) => s.status)).toEqual(["failed", "succeeded"]);
  });

  it("de-duplicates repeated events (idempotency)", async () => {
    const { repo, engine, executor } = setup();
    await repo.create(TENANT, { ...containment, steps: [containment.steps[0]!] }, "eng");
    const first = await engine.handleEvent(incidentEvent());
    const second = await engine.handleEvent(incidentEvent());
    expect(second.matches[0]!.deduplicated).toBe(true);
    expect(second.matches[0]!.execution!.id).toBe(first.matches[0]!.execution!.id);
    expect(executor.calls).toHaveLength(1);
    const third = await engine.handleEvent({ ...incidentEvent(), idempotencyKey: "outbox-77" });
    expect(third.matches[0]!.deduplicated).toBe(false);
    expect(third.matches[0]!.execution!.idempotencyKey).toBe(`outbox-77:${third.matches[0]!.playbookId}`);
  });

  it("explains non-matching conditions and ignores other triggers", async () => {
    const { repo, engine, executor } = setup();
    await repo.create(TENANT, containment, "eng");
    const res = await engine.handleEvent(incidentEvent({ severity: "medium" }));
    expect(res.matches[0]!.matched).toBe(false);
    expect(res.matches[0]!.reasons.join("\n")).toMatch(/incident\.severity ≥ "high" — actual "medium" → no match/);
    expect((await engine.handleEvent({ ...incidentEvent(), type: "alert.created" })).matches).toHaveLength(0);
    expect(executor.calls).toHaveLength(0);
  });

  it("applies global playbooks with per-organization overrides (same name)", async () => {
    const { repo, engine, executor } = setup();
    const global = (await repo.create(TENANT, { ...containment, steps: [containment.steps[0]!] }, "mssp")).playbook;
    const override = (await repo.create(TENANT, { ...containment, organizationId: ORG_B, name: "ransomware CONTAINMENT", steps: [{ id: "notify", action: "notify_analyst", parameters: {}, requireApproval: false, continueOnError: false }] }, "org-b-admin")).playbook;
    const a = await engine.handleEvent(incidentEvent({}, ORG_A));
    expect(a.matches[0]!.playbookId).toBe(global.id);
    expect(a.matches[0]!.source).toBe("global");
    const b = await engine.handleEvent({ ...incidentEvent({}, ORG_B), subjectRef: { kind: "incident", id: "inc-b" } });
    expect(b.matches).toHaveLength(1);
    expect(b.matches[0]!.playbookId).toBe(override.id);
    expect(b.matches[0]!.source).toBe("override");
    expect(executor.calls.map((c) => `${c.organizationId}:${c.action}`)).toEqual([`${ORG_A}:create_case`, `${ORG_B}:notify_analyst`]);

    // A disabled override switches the global playbook off for that organization only.
    await repo.update(TENANT, override.id, { ...containment, organizationId: ORG_B, name: "ransomware CONTAINMENT", enabled: false, steps: [{ id: "notify", action: "notify_analyst", parameters: {}, requireApproval: false, continueOnError: false }] }, "org-b-admin");
    const b2 = await engine.handleEvent({ ...incidentEvent({}, ORG_B), subjectRef: { kind: "incident", id: "inc-b2" } });
    expect(b2.matches[0]!.matched).toBe(false);
    expect(b2.matches[0]!.reasons[0]).toMatch(/disabled for this organization by an override/);
  });

  it("runs scheduled playbooks once per slot", async () => {
    const { repo, engine, executor } = setup();
    await repo.create(TENANT, { organizationId: null, name: "Nightly hunt", trigger: { on: "schedule", cron: "0 2 * * *" }, steps: [{ id: "scan", action: "run_yara_scan", parameters: {}, requireApproval: false, continueOnError: false }] }, "eng");
    const window = { tenantId: TENANT, organizationIds: [ORG_A, ORG_B], from: new Date("2026-10-07T01:55:00Z"), to: new Date("2026-10-07T02:05:00Z") };
    const first = await engine.runDueSchedules(window);
    expect(first.filter((m) => m.execution?.status === "succeeded")).toHaveLength(2);
    const again = await engine.runDueSchedules(window);
    expect(again.every((m) => m.deduplicated)).toBe(true);
    expect(executor.calls).toHaveLength(2);
    expect(await engine.runDueSchedules({ ...window, from: new Date("2026-10-07T02:05:00Z"), to: new Date("2026-10-07T03:00:00Z") })).toEqual([]);
  });

  it("manual runs require permission and the initiator cannot approve their own run", async () => {
    const { repo, engine, approvals } = setup();
    const pb = (await repo.create(TENANT, containment, "eng")).playbook;
    await expect(engine.runManual({ principal: principal("viewer", "customer_viewer"), organizationId: ORG_A, playbookId: pb.id, subject: incidentEvent().subject })).rejects.toMatchObject({ code: "forbidden" });
    const analyst = principal("frank", "incident_responder");
    const run = await engine.runManual({ principal: analyst, organizationId: ORG_A, playbookId: pb.id, subject: incidentEvent().subject, subjectRef: { kind: "incident", id: "inc-1" } });
    const exec = run.execution!;
    expect(exec.status).toBe("waiting_approval");
    await expect(approvals.approve(TENANT, exec.steps[1]!.approvalId!, analyst)).rejects.toMatchObject({ code: "self_approval" });
    await approvals.approve(TENANT, exec.steps[1]!.approvalId!, principal("grace", "incident_responder"));
    expect((await engine.getExecution(TENANT, exec.id))!.status).toBe("succeeded");
  });

  it("cancels a waiting execution and withdraws its approval", async () => {
    const { repo, engine, approvals } = setup();
    await repo.create(TENANT, containment, "eng");
    const exec = (await engine.handleEvent(incidentEvent())).matches[0]!.execution!;
    const cancelled = await engine.cancel(TENANT, exec.id, { kind: "user", id: "bob" }, "incident closed");
    expect(cancelled.status).toBe("cancelled");
    expect((await approvals.get(TENANT, exec.steps[1]!.approvalId!))!.status).toBe("cancelled");
    expect(cancelled.steps.map((s) => s.status)).toEqual(["succeeded", "cancelled", "cancelled"]);
  });

  it("snapshots the playbook version used by an execution", async () => {
    const { repo, engine, approvals } = setup();
    const created = (await repo.create(TENANT, containment, "eng")).playbook;
    const exec = (await engine.handleEvent(incidentEvent())).matches[0]!.execution!;
    await repo.update(TENANT, created.id, { ...containment, steps: [containment.steps[0]!] }, "eng");
    await approvals.approve(TENANT, exec.steps[1]!.approvalId!, principal("bob", "incident_responder"));
    const final = (await engine.getExecution(TENANT, exec.id))!;
    expect(final.playbookVersion).toBe(1);
    expect(final.steps).toHaveLength(3);
    expect(final.status).toBe("succeeded");
  });
});

describe("playbook versioning", () => {
  it("increments versions, records history and diffs, supports rollback", async () => {
    const repo = new InMemoryPlaybookRepository({ clock: new FakeClock(), ids: sequentialIds() });
    const { playbook } = await repo.create(TENANT, containment, "alice");
    expect(playbook.version).toBe(1);
    const noop = await repo.update(TENANT, playbook.id, containment, "alice");
    expect(noop.changed).toBe(false);
    expect(noop.playbook.version).toBe(1);
    const v2 = await repo.update(TENANT, playbook.id, { ...containment, description: "v2", steps: [...containment.steps.slice(0, 1), { id: "yara", action: "run_yara_scan", parameters: {}, requireApproval: false, continueOnError: true }] }, "bob", { expectedVersion: 1 });
    expect(v2.playbook.version).toBe(2);
    expect(v2.changes.map((c) => c.summary)).toEqual(expect.arrayContaining(['description changed from "Contain ransomware precursors" to "v2"', 'step "yara" (run_yara_scan) added', 'step "isolate" (isolate_endpoint) removed']));
    await expect(repo.update(TENANT, playbook.id, containment, "carol", { expectedVersion: 1 })).rejects.toMatchObject({ code: "concurrent_modification" });
    const rolled: Playbook = await repo.rollback(TENANT, playbook.id, 1, "carol");
    expect(rolled.version).toBe(3);
    expect(rolled.steps.map((s) => s.id)).toEqual(["case", "isolate", "notify"]);
    const history = await repo.versions(TENANT, playbook.id);
    expect(history.map((h) => [h.version, h.changedBy])).toEqual([
      [3, "carol"],
      [2, "bob"],
      [1, "alice"],
    ]);
    expect(history[0]!.comment).toBe("rollback to version 1");
  });

  it("validates drafts", async () => {
    const repo = new InMemoryPlaybookRepository();
    await expect(
      repo.create(TENANT, { ...containment, trigger: { on: "schedule", cron: "61 * * * *" }, steps: [containment.steps[0]!, containment.steps[0]!] }, "x"),
    ).rejects.toMatchObject({ code: "invalid_playbook" });
    await repo.create(TENANT, containment, "x");
    await expect(repo.create(TENANT, { ...containment, name: "RANSOMWARE containment " }, "x")).rejects.toMatchObject({ code: "conflict" });
  });
});
