import { SEVERITY_RANK, type AttackTechnique, type Severity } from "@bloody/contracts";
import type { CoPilotSyncPlan, CoPilotSyncReport, SyncWarning } from "@bloody/adapters";
import { normalizeHostname, stableId, type EntityRef } from "@bloody/engines";
import { SYSTEM_ACTOR, writeAudit } from "../audit/audit.js";
import type { Queryable } from "../db/pool.js";
import { toAsset, toIncident, type Row } from "../repo/mappers.js";
import type { DomainEvent, DomainEventBus } from "./domain-events.js";
import { graphFor, type InventoryService } from "./inventory.js";

/**
 * Persists a SOCFortress CoPilot synchronisation plan (`@bloody/adapters` CoPilotSync) inside
 * ONE tenant transaction. Every record is upserted idempotently on
 * `(tenant_id, external_source = "copilot:<integrationId>", external_ref)`, so re-running a sync
 * with the same snapshot changes nothing; existing Bloody records for the same host (discovered
 * from telemetry) are adopted instead of duplicated. References between records are resolved
 * in plan order (organizations → assets → agents → alerts → incidents → escalations → bindings);
 * a record whose organization is not mapped is skipped with a warning, never attached to a
 * neighbouring organization. Domain events (incident.created, escalation.created,
 * agent.unresponsive, incident.severity_changed) are published only after the commit.
 */

export type SyncCounters = Record<"organizations" | "assets" | "agents" | "alerts" | "incidents" | "escalations" | "roleBindings", number>;

export interface CoPilotSyncSummary {
  headline: string;
  externalSource: string;
  created: SyncCounters;
  updated: SyncCounters;
  unchanged: SyncCounters;
  skipped: SyncCounters;
  warnings: SyncWarning[];
  report: CoPilotSyncReport;
}

export interface PersistCoPilotInput {
  tenantId: string;
  /** The `integrations` row (id, organization_id, config). */
  integration: Row;
  plan: CoPilotSyncPlan;
  inventory: InventoryService;
  events: DomainEventBus;
  actor: string;
  now: () => number;
  /** Optional capacity guard (plan quotas) for new organizations / endpoints / users. */
  assertCapacity?: (tx: Queryable, meter: "organizations" | "endpoints" | "users", adding: number) => Promise<void>;
}

const zero = (): SyncCounters => ({ organizations: 0, assets: 0, agents: 0, alerts: 0, incidents: 0, escalations: 0, roleBindings: 0 });

function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

function iso(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  const t = Date.parse(String(v));
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

export async function persistCoPilotPlan(tx: Queryable, input: PersistCoPilotInput): Promise<{ view: CoPilotSyncSummary; afterCommit: () => void }> {
  const { tenantId, plan, integration, inventory } = input;
  const integrationId = String(integration.id);
  const source = `copilot:${integrationId}`;
  const scopedOrg = (integration.organization_id as string | null) ?? null;
  const created = zero();
  const updated = zero();
  const unchanged = zero();
  const skipped = zero();
  const warnings: SyncWarning[] = [...plan.warnings];
  const pending: DomainEvent[] = [];
  const nowIso = () => new Date(input.now()).toISOString();
  const actor = SYSTEM_ACTOR(tenantId, `integration:${integrationId}`);
  if (plan.tenantId !== tenantId) throw new Error("CoPilot plan belongs to another tenant");

  // ─── Organizations ─────────────────────────────────────────────────────
  const orgByRef = new Map<string, string>();
  const orgNames = new Map<string, string>();
  const unmappedForScoped = plan.organizations.filter((o) => !o.organizationId);
  for (const o of plan.organizations) {
    let orgId: string | null = null;
    if (o.organizationId) {
      const { rows } = await tx.query<{ id: string; name: string }>("SELECT id, name FROM organizations WHERE id = $1", [o.organizationId]);
      if (!rows[0]) {
        warnings.push({ code: "override_not_found", message: `Organization override ${o.organizationId} for ${o.meta.customerCode} does not exist in this tenant`, ref: o.externalRef });
        skipped.organizations++;
        continue;
      }
      if (scopedOrg && rows[0].id !== scopedOrg) {
        warnings.push({ code: "out_of_scope", message: `Customer ${o.meta.customerCode} maps outside the integration's organization`, ref: o.externalRef });
        skipped.organizations++;
        continue;
      }
      orgId = rows[0].id;
      orgNames.set(orgId, rows[0].name);
      unchanged.organizations++;
    } else if (scopedOrg) {
      // Organization-scoped integration: everything lands in that organization, but only when the
      // snapshot contains exactly one customer (otherwise we cannot tell customers apart safely).
      if (unmappedForScoped.length !== 1) {
        warnings.push({ code: "ambiguous_scope", message: `Organization-scoped integration received ${unmappedForScoped.length} customers; configure organizationOverrides`, ref: o.externalRef });
        skipped.organizations++;
        continue;
      }
      orgId = scopedOrg;
      unchanged.organizations++;
    } else {
      const parentId = o.parentExternalRef ? (orgByRef.get(o.parentExternalRef) ?? null) : null;
      const { rows } = await tx.query<Row>("SELECT id, name, parent_organization_id, retention_days FROM organizations WHERE external_source = $1 AND external_ref = $2", [source, o.externalRef]);
      const cur = rows[0];
      if (cur) {
        orgId = String(cur.id);
        if (cur.name !== o.data.name || (cur.parent_organization_id ?? null) !== parentId) {
          await tx.query("UPDATE organizations SET name = $2, parent_organization_id = $3 WHERE id = $1", [orgId, o.data.name, parentId]);
          updated.organizations++;
        } else unchanged.organizations++;
      } else {
        await input.assertCapacity?.(tx, "organizations", 1);
        let slug = o.data.slug;
        const taken = await tx.query<{ slug: string }>("SELECT slug FROM organizations WHERE slug = $1 OR slug LIKE $2", [slug, `${slug.slice(0, 54)}-%`]);
        const used = new Set(taken.rows.map((r) => r.slug));
        for (let i = 2; used.has(slug); i++) slug = `${o.data.slug.slice(0, 54)}-${i}`;
        const ins = await tx.query<{ id: string }>(
          `INSERT INTO organizations (tenant_id, parent_organization_id, name, slug, retention_days, status, external_source, external_ref, settings)
           VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, $8::jsonb) RETURNING id`,
          [tenantId, parentId, o.data.name, slug, o.data.retentionDays, source, o.externalRef, JSON.stringify({ copilot: { customerCode: o.meta.customerCode, customerType: o.meta.customerType, contact: o.contact } })],
        );
        orgId = ins.rows[0]!.id;
        created.organizations++;
        await writeAudit(tx, actor, { action: "organization.created", organizationId: orgId, targetKind: "organization", targetId: orgId, details: { source: "copilot", customerCode: o.meta.customerCode, slug } });
      }
      orgNames.set(orgId, o.data.name);
    }
    orgByRef.set(o.externalRef, orgId);
  }
  const orgOf = (ref: string, what: keyof SyncCounters, recordRef: string): string | null => {
    const id = orgByRef.get(ref);
    if (!id) {
      skipped[what]++;
      warnings.push({ code: "organization_unmapped", message: `${what} skipped: organization ${ref} is not mapped`, ref: recordRef });
      return null;
    }
    return id;
  };

  // ─── Assets ────────────────────────────────────────────────────────────
  const assetByRef = new Map<string, string>();
  for (const a of plan.assets) {
    const orgId = orgOf(a.organizationRef, "assets", a.externalRef);
    if (!orgId) continue;
    const d = a.data;
    let { rows } = await tx.query<Row>("SELECT * FROM assets WHERE external_source = $1 AND external_ref = $2", [source, a.externalRef]);
    if (!rows[0] && d.hostname) {
      // Adopt a host already known from telemetry instead of duplicating it.
      ({ rows } = await tx.query<Row>("SELECT * FROM assets WHERE organization_id = $1 AND hostname IS NOT NULL AND lower(hostname) = lower($2)", [orgId, d.hostname]));
    }
    const cur = rows[0];
    if (cur && String(cur.organization_id) !== orgId) {
      skipped.assets++;
      warnings.push({ code: "asset_org_mismatch", message: `Asset ${a.externalRef} already belongs to another organization`, ref: a.externalRef });
      continue;
    }
    if (cur) {
      const patch = {
        kind: d.kind,
        name: d.name,
        hostname: d.hostname ?? null,
        ipAddresses: d.ipAddresses,
        os: d.os ?? null,
        criticality: d.criticality,
        internetFacing: d.internetFacing,
        tags: [...new Set([...((cur.tags as string[]) ?? []), ...d.tags])],
      };
      const changed =
        cur.kind !== patch.kind ||
        cur.name !== patch.name ||
        (cur.hostname ?? null) !== patch.hostname ||
        !sameJson(cur.ip_addresses, patch.ipAddresses) ||
        (cur.os ?? null) !== patch.os ||
        cur.criticality !== patch.criticality ||
        Boolean(cur.internet_facing) !== patch.internetFacing ||
        !sameJson(cur.tags, patch.tags) ||
        cur.external_ref !== a.externalRef;
      if (cur.external_ref !== a.externalRef) await tx.query("UPDATE assets SET external_source = $2, external_ref = $3, source = 'integration' WHERE id = $1", [cur.id, source, a.externalRef]);
      if (a.lastSeenAt) await tx.query("UPDATE assets SET last_seen_at = GREATEST(coalesce(last_seen_at, $2::timestamptz), $2::timestamptz) WHERE id = $1", [cur.id, a.lastSeenAt]);
      if (changed) {
        await inventory.updateAsset(tx, tenantId, String(cur.id), patch);
        updated.assets++;
      } else unchanged.assets++;
      assetByRef.set(a.externalRef, String(cur.id));
    } else {
      const asset = await inventory.createAsset(tx, tenantId, orgId, {
        kind: d.kind,
        name: d.name,
        hostname: d.hostname ?? null,
        ipAddresses: d.ipAddresses,
        os: d.os ?? null,
        criticality: d.criticality,
        internetFacing: d.internetFacing,
        tags: d.tags,
        owner: d.owner ?? null,
        source: "integration",
        externalSource: source,
        externalRef: a.externalRef,
        lastSeenAt: a.lastSeenAt,
      });
      assetByRef.set(a.externalRef, asset.id);
      created.assets++;
    }
  }

  // ─── Agents ────────────────────────────────────────────────────────────
  const newAgents = plan.agents.length;
  let checkedEndpointCapacity = false;
  for (const g of plan.agents) {
    const orgId = orgOf(g.organizationRef, "agents", g.externalRef);
    if (!orgId) continue;
    const assetId = assetByRef.get(g.assetRef) ?? null;
    const d = g.data;
    let { rows } = await tx.query<Row>("SELECT * FROM agents WHERE external_source = $1 AND external_ref = $2", [source, g.externalRef]);
    if (!rows[0]) ({ rows } = await tx.query<Row>("SELECT * FROM agents WHERE organization_id = $1 AND lower(hostname) = lower($2) AND engine = $3", [orgId, d.hostname, d.engine]));
    const cur = rows[0];
    const engineRefs = { wazuh: g.engines.wazuhAgentId, ...(g.engines.velociraptorClientId ? { velociraptor: g.engines.velociraptorClientId } : {}) };
    if (cur) {
      const next = {
        asset_id: assetId ?? cur.asset_id ?? null,
        platform: d.platform,
        version: d.version,
        status: d.status,
        last_checkin_at: d.lastCheckinAt ?? cur.last_checkin_at ?? null,
        antivirus_status: d.antivirusStatus ?? cur.antivirus_status,
        firewall_enabled: d.firewallEnabled ?? cur.firewall_enabled,
        engine_refs: { ...((cur.engine_refs as Record<string, unknown>) ?? {}), ...engineRefs },
      };
      const changed =
        (cur.asset_id ?? null) !== next.asset_id ||
        cur.platform !== next.platform ||
        cur.version !== next.version ||
        cur.status !== next.status ||
        iso(cur.last_checkin_at) !== iso(next.last_checkin_at) ||
        cur.antivirus_status !== next.antivirus_status ||
        Boolean(cur.firewall_enabled) !== Boolean(next.firewall_enabled) ||
        !sameJson(cur.engine_refs, next.engine_refs) ||
        cur.external_ref !== g.externalRef;
      if (changed) {
        await tx.query(
          `UPDATE agents SET asset_id = $2, platform = $3, version = $4, status = $5, last_checkin_at = $6, antivirus_status = $7, firewall_enabled = $8,
                  engine_refs = $9::jsonb, external_source = $10, external_ref = $11 WHERE id = $1`,
          [cur.id, next.asset_id, next.platform, next.version, next.status, next.last_checkin_at, next.antivirus_status, next.firewall_enabled, JSON.stringify(next.engine_refs), source, g.externalRef],
        );
        updated.agents++;
        if (next.status === "unresponsive" && cur.status !== "unresponsive") {
          pending.push({ tenantId, organizationId: orgId, event: "agent.unresponsive", occurredAt: nowIso(), severity: "medium", subject: { kind: "agent", id: String(cur.id), label: d.hostname }, dedupKey: `agent:${String(cur.id)}:unresponsive`, data: { reason: g.statusReason, source: "copilot" } });
        }
      } else unchanged.agents++;
    } else {
      if (!checkedEndpointCapacity) {
        await input.assertCapacity?.(tx, "endpoints", newAgents);
        checkedEndpointCapacity = true;
      }
      const ins = await tx.query<{ id: string }>(
        `INSERT INTO agents (tenant_id, organization_id, asset_id, hostname, platform, version, engine, status, last_checkin_at, antivirus_status, firewall_enabled, external_source, external_ref, engine_refs)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb) RETURNING id`,
        [tenantId, orgId, assetId, d.hostname, d.platform, d.version, d.engine, d.status, d.lastCheckinAt, d.antivirusStatus ?? "unmanaged", d.firewallEnabled ?? false, source, g.externalRef, JSON.stringify(engineRefs)],
      );
      created.agents++;
      if (d.status === "unresponsive") {
        pending.push({ tenantId, organizationId: orgId, event: "agent.unresponsive", occurredAt: nowIso(), severity: "medium", subject: { kind: "agent", id: ins.rows[0]!.id, label: d.hostname }, dedupKey: `agent:${ins.rows[0]!.id}:unresponsive`, data: { reason: g.statusReason, source: "copilot" } });
      }
    }
    // Asset graph/risk reflects the agent (EDR coverage, isolation).
    if (assetId) {
      const { rows: arows } = await tx.query<Row>("SELECT * FROM assets WHERE id = $1", [assetId]);
      if (arows[0]) await inventory.syncAssetGraph(tx, tenantId, toAsset(arows[0]));
    }
  }

  // ─── Alerts ────────────────────────────────────────────────────────────
  const alertByRef = new Map<string, string>();
  const assetIdsByHint = async (orgId: string, hints: string[]): Promise<string[]> => {
    const keys = hints.map((h) => normalizeHostname(h)).filter((k): k is string => Boolean(k));
    if (keys.length === 0) return [];
    const { rows } = await tx.query<{ id: string }>("SELECT id FROM assets WHERE organization_id = $1 AND hostname IS NOT NULL AND split_part(lower(hostname), '.', 1) = ANY($2::text[])", [orgId, keys]);
    return rows.map((r) => r.id);
  };
  for (const al of plan.alerts) {
    const orgId = orgOf(al.organizationRef, "alerts", al.externalRef);
    if (!orgId) continue;
    const d = al.data;
    const assetIds = [...al.assetRefs.map((r) => assetByRef.get(r)).filter((x): x is string => Boolean(x)), ...(await assetIdsByHint(orgId, al.assetHints))];
    const explanation = [...al.explanation, ...al.riskFactors.map((f) => `${f.label}: ${f.explanation}`)];
    const { rows } = await tx.query<Row>("SELECT * FROM alerts WHERE external_source = $1 AND external_ref = $2", [source, al.externalRef]);
    const cur = rows[0];
    if (cur) {
      const changed =
        cur.title !== d.title.slice(0, 500) ||
        cur.severity !== d.severity ||
        cur.status !== d.status ||
        Number(cur.risk_score) !== d.riskScore ||
        iso(cur.last_seen_at) !== iso(d.lastSeenAt) ||
        (cur.asset_id ?? null) !== (assetIds[0] ?? cur.asset_id ?? null);
      if (changed) {
        await tx.query(
          `UPDATE alerts SET title = $2, severity = $3, status = $4, risk_score = $5, confidence = $6, last_seen_at = $7, attack = $8::jsonb, explanation = $9::jsonb,
                  asset_id = coalesce($10, asset_id), indicators = $11::jsonb WHERE id = $1`,
          [cur.id, d.title.slice(0, 500), d.severity, d.riskScore, d.confidence, d.lastSeenAt, JSON.stringify(d.attack), JSON.stringify(explanation), assetIds[0] ?? null, JSON.stringify(al.indicators)],
        );
        updated.alerts++;
      } else unchanged.alerts++;
      alertByRef.set(al.externalRef, String(cur.id));
    } else {
      const id = stableId("copilot-alert", tenantId, source, al.externalRef);
      await tx.query(
        `INSERT INTO alerts (id, tenant_id, organization_id, title, severity, status, rule_id, rule_kind, source, asset_id, attack, confidence, risk_score, explanation, indicators,
                             first_seen_at, last_seen_at, external_source, external_ref)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'external', $8, $9, $10::jsonb, $11, $12, $13::jsonb, $14::jsonb, $15, $16, $17, $18)
         ON CONFLICT (id) DO NOTHING`,
        [id, tenantId, orgId, d.title.slice(0, 500), d.severity, d.status, d.ruleId, d.source, assetIds[0] ?? null, JSON.stringify(d.attack), d.confidence, d.riskScore, JSON.stringify(explanation), JSON.stringify(al.indicators), d.firstSeenAt, d.lastSeenAt, source, al.externalRef],
      );
      alertByRef.set(al.externalRef, id);
      created.alerts++;
      pending.push({ tenantId, organizationId: orgId, event: "alert.created", occurredAt: nowIso(), severity: d.severity, subject: { kind: "alert", id, label: d.title }, data: { source: "copilot", ruleId: d.ruleId } });
    }
  }

  // ─── Incidents (CoPilot cases) ─────────────────────────────────────────
  const incidentByRef = new Map<string, string>();
  for (const c of plan.incidents) {
    const orgId = orgOf(c.organizationRef, "incidents", c.externalRef);
    if (!orgId) continue;
    const d = c.data;
    const alertIds = c.alertRefs.map((r) => alertByRef.get(r)).filter((x): x is string => Boolean(x));
    const assetIds = [...new Set(c.assetRefs.map((r) => assetByRef.get(r)).filter((x): x is string => Boolean(x)))];
    const risk = { score: d.riskScore, severity: d.severity, factors: c.riskFactors, summary: c.explanation.join(" "), modelVersion: "copilot-sync/1" };
    const { rows } = await tx.query<Row>("SELECT * FROM incidents WHERE external_source = $1 AND external_ref = $2", [source, c.externalRef]);
    const cur = rows[0];
    let incidentId: string;
    if (cur) {
      incidentId = String(cur.id);
      const changed =
        cur.title !== d.title || (cur.summary ?? null) !== d.summary || cur.severity !== d.severity || cur.status !== d.status || Number(cur.risk_score) !== d.riskScore || iso(cur.closed_at) !== iso(d.closedAt) || !sameJson(cur.asset_ids, assetIds);
      if (changed) {
        await tx.query(
          `UPDATE incidents SET title = $2, summary = $3, severity = $4, status = $5, risk_score = $6, risk = $7::jsonb, attack = $8::jsonb, closed_at = $9, asset_ids = $10::uuid[],
                  acknowledged_at = CASE WHEN $5 <> 'new' THEN coalesce(acknowledged_at, now()) ELSE acknowledged_at END WHERE id = $1`,
          [incidentId, d.title, d.summary, d.severity, d.status, d.riskScore, JSON.stringify(risk), JSON.stringify(d.attack), d.closedAt, assetIds],
        );
        updated.incidents++;
        if (SEVERITY_RANK[d.severity] > SEVERITY_RANK[cur.severity as Severity]) {
          pending.push({ tenantId, organizationId: orgId, event: "incident.severity_changed", occurredAt: nowIso(), severity: d.severity, subject: { kind: "incident", id: incidentId, label: d.title }, data: { from: cur.severity, to: d.severity, source: "copilot" } });
        }
      } else unchanged.incidents++;
    } else {
      const ins = await tx.query<Row>(
        `INSERT INTO incidents (tenant_id, organization_id, number, title, summary, severity, status, risk_score, risk, attack, asset_ids, source, detected_at, closed_at,
                                acknowledged_at, created_by, external_source, external_ref)
         VALUES ($1, $2, next_incident_number($1), $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::uuid[], 'integration', $11, $12, CASE WHEN $6 <> 'new' THEN $11::timestamptz END, $13, $14, $15)
         RETURNING *`,
        [tenantId, orgId, d.title.length >= 3 ? d.title.slice(0, 300) : `CoPilot case ${c.externalRef}`, d.summary, d.severity, d.status, d.riskScore, JSON.stringify(risk), JSON.stringify(d.attack), assetIds, d.detectedAt, d.closedAt, `integration:${integrationId}`, source, c.externalRef],
      );
      incidentId = String(ins.rows[0]!.id);
      created.incidents++;
      const view = toIncident(ins.rows[0]!);
      await writeAudit(tx, actor, { action: "incident.created", organizationId: orgId, targetKind: "incident", targetId: incidentId, details: { number: view.number, severity: view.severity, source: "copilot", externalRef: c.externalRef } });
      pending.push({ tenantId, organizationId: orgId, event: "incident.created", occurredAt: nowIso(), severity: d.severity, subject: { kind: "incident", id: incidentId, label: view.title }, data: { number: view.number, riskScore: view.riskScore, summary: view.summary, source: "copilot" } });
      // Security Graph: link the case to its hosts and techniques.
      const assets = assetIds.length ? (await tx.query<Row>("SELECT id, name, hostname FROM assets WHERE id = ANY($1::uuid[])", [assetIds])).rows : [];
      const entities: EntityRef[] = assets.map((a) => ({ kind: "endpoint", key: (typeof a.hostname === "string" ? normalizeHostname(a.hostname) : null) ?? `asset:${String(a.id)}`, label: String(a.name) }));
      try {
        await tx.query("SAVEPOINT copilot_link");
        await graphFor(tx, tenantId).linkIncident({ incidentId, organizationId: orgId, title: view.title, severity: view.severity, status: view.status, detectedAt: view.detectedAt, entities, techniques: d.attack as AttackTechnique[] });
        await tx.query("RELEASE SAVEPOINT copilot_link");
      } catch {
        await tx.query("ROLLBACK TO SAVEPOINT copilot_link");
        warnings.push({ code: "graph_link_failed", message: `Could not link case ${c.externalRef} into the Security Graph`, ref: c.externalRef });
      }
    }
    if (alertIds.length > 0) {
      await tx.query(
        `INSERT INTO incident_alerts (incident_id, alert_id, tenant_id, organization_id)
         SELECT $1, a.id, a.tenant_id, a.organization_id FROM alerts a WHERE a.id = ANY($2::uuid[]) AND a.organization_id = $3 ON CONFLICT DO NOTHING`,
        [incidentId, alertIds, orgId],
      );
      await tx.query("UPDATE alerts SET incident_id = $1 WHERE id = ANY($2::uuid[]) AND organization_id = $3 AND incident_id IS DISTINCT FROM $1", [incidentId, alertIds, orgId]);
      await tx.query("UPDATE incidents SET alert_count = (SELECT count(*) FROM incident_alerts WHERE incident_id = $1) WHERE id = $1 AND alert_count <> (SELECT count(*) FROM incident_alerts WHERE incident_id = $1)", [incidentId]);
    }
    incidentByRef.set(c.externalRef, incidentId);
  }

  // ─── Escalations ──────────────────────────────────────────────────────
  for (const e of plan.escalations) {
    const orgId = orgOf(e.organizationRef, "escalations", e.externalRef);
    if (!orgId) continue;
    const incidentId = e.incidentRef ? (incidentByRef.get(e.incidentRef) ?? null) : null;
    const d = e.data;
    const { rows } = await tx.query<Row>("SELECT * FROM escalations WHERE external_source = $1 AND external_ref = $2", [source, e.externalRef]);
    const cur = rows[0];
    if (cur) {
      const changed = cur.status !== d.status || cur.severity !== d.severity || cur.title !== d.title || iso(cur.due_at) !== iso(d.dueAt) || iso(cur.resolved_at) !== iso(d.resolvedAt);
      if (changed) {
        await tx.query(
          `UPDATE escalations SET title = $2, severity = $3, status = $4, due_at = $5, resolved_at = $6,
                  acknowledged_at = CASE WHEN $4 <> 'open' THEN coalesce(acknowledged_at, now()) ELSE acknowledged_at END WHERE id = $1`,
          [cur.id, d.title, d.severity, d.status, d.dueAt, d.resolvedAt],
        );
        updated.escalations++;
      } else unchanged.escalations++;
      continue;
    }
    const ins = await tx.query<{ id: string }>(
      `INSERT INTO escalations (tenant_id, organization_id, incident_id, title, reason, severity, status, due_at, resolved_at, created_by, external_source, external_ref)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT DO NOTHING RETURNING id`,
      [tenantId, orgId, incidentId, d.title.length >= 3 ? d.title.slice(0, 300) : `CoPilot escalation ${e.externalRef}`, e.reason.slice(0, 2000), d.severity, d.status, d.dueAt, d.resolvedAt, `integration:${integrationId}`, source, e.externalRef],
    );
    if (!ins.rows[0]) {
      skipped.escalations++;
      warnings.push({ code: "escalation_exists", message: "The incident already has an open escalation; the CoPilot escalation was not duplicated", ref: e.externalRef });
      continue;
    }
    created.escalations++;
    if (d.status !== "resolved") {
      pending.push({ tenantId, organizationId: orgId, event: "escalation.created", occurredAt: nowIso(), severity: d.severity, subject: { kind: "escalation", id: ins.rows[0].id, label: d.title }, data: { incidentId, kind: e.kind, source: "copilot" } });
    }
  }

  // ─── Customer-portal users → customer_viewer bindings ─────────────────
  for (const b of plan.roleBindings) {
    const orgId = orgOf(b.organizationRef, "roleBindings", b.externalRef);
    if (!orgId) continue;
    const email = b.user.email?.trim().toLowerCase() ?? null;
    let { rows } = await tx.query<{ id: string }>("SELECT id FROM users WHERE external_source = $1 AND external_ref = $2", [source, b.user.externalRef]);
    if (!rows[0] && email) ({ rows } = await tx.query<{ id: string }>("SELECT id FROM users WHERE email = $1", [email]));
    let userId = rows[0]?.id ?? null;
    if (!userId) {
      if (!email || !/^[^@\s]+@[^@\s]+$/.test(email)) {
        skipped.roleBindings++;
        warnings.push({ code: "user_without_email", message: `Portal user ${b.user.username} has no e-mail address; no Bloody account was invited`, ref: b.externalRef });
        continue;
      }
      await input.assertCapacity?.(tx, "users", 1);
      const ins = await tx.query<{ id: string }>(
        "INSERT INTO users (tenant_id, organization_id, email, display_name, status, external_source, external_ref) VALUES ($1, $2, $3, $4, 'invited', $5, $6) RETURNING id",
        [tenantId, orgId, email, b.user.username.slice(0, 200), source, b.user.externalRef],
      );
      userId = ins.rows[0]!.id;
      await writeAudit(tx, actor, { action: "user.invited", organizationId: orgId, targetKind: "user", targetId: userId, details: { source: "copilot", reason: b.reason } });
    }
    const bind = await tx.query(
      `INSERT INTO role_bindings (tenant_id, principal_kind, principal_id, role, organization_id) VALUES ($1, 'user', $2, 'customer_viewer', $3)
       ON CONFLICT (tenant_id, principal_kind, principal_id, role, org_key(organization_id)) DO NOTHING`,
      [tenantId, userId, orgId],
    );
    if ((bind.rowCount ?? 0) > 0) created.roleBindings++;
    else unchanged.roleBindings++;
  }

  const total = (c: SyncCounters) => Object.values(c).reduce((a, b) => a + b, 0);
  const headline = `${plan.report.headline} — ${total(created)} created, ${total(updated)} updated, ${total(unchanged)} unchanged${total(skipped) ? `, ${total(skipped)} skipped` : ""}`;
  await writeAudit(tx, { ...actor, actorId: input.actor, actorLabel: input.actor }, {
    action: "integration.sync",
    organizationId: scopedOrg,
    targetKind: "integration",
    targetId: integrationId,
    details: { engine: "copilot", created, updated, skipped, warnings: warnings.length, totals: plan.report.totals, fetchedAt: plan.source.fetchedAt },
  });

  const view: CoPilotSyncSummary = { headline, externalSource: source, created, updated, unchanged, skipped, warnings: warnings.slice(0, 200), report: plan.report };
  return {
    view,
    afterCommit: () => {
      for (const e of pending) input.events.publish(e);
    },
  };
}
