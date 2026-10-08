# ADR-0009: MSSP tenancy model and customer portal

- Status: Accepted
- Date: 2026-10-07
- Deciders: Product, platform architecture, security engineering

## Context

MSSP/MDR support is a first-class requirement. An MSSP must be able to:

- manage hundreds of customer organizations, switch between them, and see aggregate posture;
- assign analysts and teams per customer;
- define global playbooks with per-customer overrides;
- aggregate and escalate incidents, compare customer risk and produce customer reports;
- manage subscriptions, agent health, integrations and AI policies.

Customers must see **their** dashboard, escalations, reports and module trials, and nothing of
other customers. Enterprises with business units need the same structure without the MSSP
commercial layer.

## Decision

1. **One hierarchy for both models** (ADR-0002): Account (`kind = mssp | enterprise`) →
   Organizations.
   - For an MSSP, each customer is an Organization. Sub-organizations
     (`parentOrganizationId`) model customer business units or sites.
   - For an enterprise, Organizations are business units or subsidiaries.
   - Each organization has its own retention (`retentionDays`), entitlements and integrations.
2. **Role bindings are scoped** (`RoleBinding{role, organizationId | null}`).
   - MSSP staff hold tenant-wide bindings (`mssp_admin`, analysts, hunters, responders,
     engineers) or bindings per customer, for dedicated teams.
   - Customer users hold bindings on their own organization only (`org_admin`, `ciso`,
     `executive`, `customer_viewer`).
   - `principalCan` never lets an organization binding grant tenant-level actions.
   - `principalOrgScope` filters every list endpoint.
3. **The customer portal is the same application**, scoped by role. There is no second codebase
   and no data copy.
   - Role-aware dashboards (`DashboardRole`) select widget presets.
   - Navigation hides the MSSP portfolio, other organizations and tenant settings.
   - Customers acknowledge and resolve escalations (`escalation:write`), read reports, and
     start module trials.
4. **The MSSP Command Center** (`GET /api/v1/mssp/overview` → `MsspOverview`) aggregates
   per-customer data: risk score, active and critical incidents, agents and unhealthy agents,
   SLA breaches and MRR. It is computed from the same tenant-scoped tables, so there is no
   separate warehouse to leak from.
5. **Commercial layer, decoupled from security logic.**
   - Plans (`PLANS`: trial, essentials, professional, enterprise, mssp) define modules and
     limits: endpoints, organizations, users, events per day, retention and AI requests.
   - `entitlements` per organization record module state (active, trial, trial ended,
     available, locked). `usage_counters` meter events, endpoints and AI usage per
     organization per day.
   - Security code asks only "is module X entitled for org Y?" and never knows prices.
   - Billing systems integrate through usage exports and entitlement webhooks.
6. **White-label and contacts.** Customer-facing reports carry the MSSP's branding (reporting
   `branding`). Commercial links (sales, support, docs, hub) are build-time configuration of the
   web app, hidden when unset, and never hard-coded.
7. **Data residency.** `Account.dataRegion` pins where a tenant's data lives. Regional
   deployments are separate stacks with the same code, and an MSSP may spread customers across
   regions with one account per region.

## Consequences

- One isolation mechanism (tenant RLS plus org-scoped RBAC) serves MSSPs, enterprises and
  customers. Security review covers one model, not three.
- MSSP analysts move between customers without re-authenticating. Every action is still audited
  with the organization it touched.
- Customers get a real portal on day one, with the same features and permissions model. Feature
  work for analysts benefits customers automatically when their roles allow it.
- Cross-account features for an MSSP spread over several regional accounts (portfolio across
  regions) need an explicit federation layer later. That is deferred.

## Alternatives considered

- **Separate customer-portal application.** Duplicated UI and API, divergent permissions, and a
  second attack surface. Rejected.
- **One account per customer, MSSP as a "super-tenant" crossing RLS.** That would require
  cross-tenant queries for every MSSP screen and weaken the hard isolation boundary. Rejected;
  MSSP customers live inside the MSSP's account as organizations.
- **Billing embedded in the security domain** (price-aware detections, quota checks inside
  engines). Rejected: entitlements are a separate service boundary.
