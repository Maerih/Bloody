## What & why

<!-- One paragraph: the change and the problem it solves. Link the issue / ADR. -->

## Checklist

- [ ] **Tenant isolation** — every new customer-data table/row has `tenant_id` + `organization_id`, RLS policy added, handlers derive tenancy from the principal (never the request body).
- [ ] **No mock data in production paths** — demo data only in `apps/api/src/db/seed-dev.ts` / test fixtures; UI renders API responses and real empty states.
- [ ] **Explainability** — every new score carries `RiskFactor[]`.
- [ ] **Dangerous actions** — RBAC permission + approval gate + audit record; AI tool tier respected.
- [ ] **Licences** — no source copied from open-source projects; new npm deps are permissive (`node scripts/license-check.mjs` passes); new engines run as separate unmodified services (ADR-0004, `docs/LICENSES.md` updated).
- [ ] **Contracts** — `packages/contracts` changes are additive (or versioned with a migration note).
- [ ] **Tests** — `pnpm -r typecheck` and `pnpm -r test` pass; API changes covered by integration tests against real Postgres.
- [ ] **Operations** — migrations are expand/contract-safe; new config documented in `.env.example` / `docs/OPERATIONS.md`.
