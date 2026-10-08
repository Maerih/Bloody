# ADR-0002: Tenancy in PostgreSQL with row-level security

- Status: Accepted
- Date: 2026-10-07
- Deciders: Platform architecture, security engineering

## Context

Bloody is multi-tenant SaaS. An MSSP account manages hundreds of customer organizations, and one
customer's data must never be visible to another tenant. In this domain a cross-tenant leak would
be catastrophic: it would expose alerts, credentials found in evidence and vulnerability data.
Application-level filtering alone fails open: one forgotten `WHERE tenant_id = $1` is a breach.
The isolation boundary must also survive future code paths: background jobs, the AI context
builder, report generation and ad-hoc SQL.

## Decision

**Hierarchy.** Platform → Account (`tenant_id`, hard isolation, `kind = mssp | enterprise`) →
Organization (`organization_id`, the delegated-administration boundary). Every customer-data row
carries both columns (`packages/contracts/src/tenancy.ts`). The only exceptions are tenant-wide
configuration rows, where `organization_id` may be NULL.

**First line: the API.**

- The tenant is always derived from the authenticated principal (session, JWT or API key),
  never from a request body, query or header.
- Handlers check `principalCan(principal, permission, organizationId)` and filter list
  endpoints with `principalOrgScope()`.
- Request-path SQL runs only inside `Database.withTenant(tenantId, fn)`
  (`apps/api/src/db/pool.ts`), which opens a transaction and sets the transaction-local GUC
  with `set_config('app.tenant_id', $1, true)`.

**Second line: PostgreSQL RLS** (`apps/api/migrations/0009_row_level_security.sql`).

- Every table with a `tenant_id` column gets `ENABLE` and `FORCE ROW LEVEL SECURITY` and a
  policy `tenant_isolation`:
  `USING / WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)`.
  Without the GUC, a query sees nothing and can write nothing.
- The API's runtime role `bloody_app` is `NOSUPERUSER NOBYPASSRLS NOINHERIT` and owns no
  table. RLS therefore always applies, even to code that forgets its predicate.
- The schema owner `bloody_owner` is used only by the migration runner. The API never holds its
  credentials: in deployments `DATABASE_URL` and `DATABASE_APP_URL` are both the runtime role.
- The migration runner re-applies least-privilege grants after every run:
  - `audit_log` is append-only (SELECT and INSERT);
  - `auth_lookup` is read-only;
  - partitions are reachable only through their parent.

  The runner then **refuses to finish** if any tenant table lacks `ENABLE` + `FORCE` RLS
  (`verifyRowLevelSecurity`).
- Pre-authentication lookups (login e-mail, API-key prefix → tenant) use one directory table,
  `auth_lookup`, which holds digests only. It is the single table readable without a tenant
  context.

**Referential integrity across the boundary.** Child rows reference organizations through
composite foreign keys `(tenant_id, organization_id) → organizations (tenant_id, id)`, so a row
can never point at another tenant's organization.

**Outside Postgres.** The same boundary applies everywhere else:

- cache and object-storage keys are prefixed `t/{tenantId}/o/{orgId}/…`;
- Kafka messages are keyed by tenant;
- the AI context builder only reads through `withTenant`;
- reports are rendered from tenant-scoped data sources;
- OpenSearch (when enabled) uses per-tenant index patterns with matching roles.

## Consequences

- A missing predicate in a handler returns an empty result or fails a write. It never leaks.
- Every request-path query runs in a transaction (one extra round-trip for `set_config`), which
  is acceptable at control-plane volumes. Bulk ingest uses array `unnest` inserts, so the cost is
  per batch.
- Cross-tenant operations (platform administration, MSSP billing roll-ups across accounts) need
  explicit privileged code paths. Those paths are audited and never reachable from tenant
  request handlers.
- Organization-level isolation *inside* a tenant is enforced by the API (RBAC bindings per
  organization), not by RLS. That is deliberate: MSSP analysts legitimately work across the
  organizations of their own account. A future ADR may add an `app.organization_ids` GUC for
  customer-scoped principals as defence in depth.
- Connection poolers must use transaction pooling with `SET LOCAL` semantics (PgBouncer
  `pool_mode = transaction` is fine, because `set_config(..., true)` is transaction-scoped).

## Alternatives considered

- **Database per tenant.** This gives the strongest isolation, but connection counts, migrations
  and analytics across hundreds of MSSP customers become operationally heavy. We keep it as a
  premium "dedicated deployment" option: the same code and schema, one tenant per cluster.
- **Schema per tenant.** It has the same migration fan-out problem, and `search_path` mistakes
  fail open. Rejected.
- **Application filtering only.** It fails open on the first bug. Rejected.
- **Citus or another sharded Postgres.** Compatible with this design (distribute by `tenant_id`)
  once a single primary is no longer enough. Deferred.
