# ADR-0001: TypeScript monorepo and modular monolith

- Status: Accepted
- Date: 2026-10-07
- Deciders: Platform architecture, engineering leads

## Context

Bloody covers about twenty product modules (EDR, XDR, ITDR, NDR, SIEM, ASM, the posture modules,
VM, CTI, DFIR, SOAR, AI SOC) for three audiences: MSSP operators, SOC analysts and customers. They
all share one Security Graph, one Risk Engine, one canonical event schema, one RBAC model and one
API. The team is small, and the domain model will change a great deal in the first releases.
Customers will deploy Bloody as SaaS, on managed Kubernetes, customer-hosted, hybrid and, later,
air-gapped. The proprietary code must stay testable without Docker.

The forces at play:

- Shared types must flow end to end: the canonical event, entities, RBAC, entitlements and API
  DTOs are used by the API, the analytics engines, the adapters, the AI layer and the UI. When one
  side changes, the compiler must fail every other side that is now out of step.
- Detection, correlation, risk and graph logic must be unit-testable as pure code, with no
  database, broker or engine running.
- Early microservices would cost distributed transactions, network failure modes and N
  deployment pipelines, before we even know where the scaling seams are.

## Decision

1. **One pnpm workspace** (`pnpm-workspace.yaml`), TypeScript `strict`, ESM with `NodeNext`
   resolution, Node 22. Packages export their TypeScript source (`src/index.ts`). The API bundles
   them with tsup (`noExternal: [/^@bloody\//]`), so the runtime image ships compiled JavaScript
   and no workspace links.
2. **Layered packages with injected I/O.**
   - `@bloody/contracts`: zod schemas and types. Every other package depends on it, and it
     depends on no other package. Changes are additive, or versioned.
   - `@bloody/engines`, `@bloody/ai`, `@bloody/adapters`, `@bloody/automation` and
     `@bloody/reporting`: pure domain logic. Storage, HTTP, clock and id generation reach them
     only through interfaces (`SqlGraphStore`, `EventBus`, `Clock`, `fetch`, …). Packages never
     import from `apps/*`.
   - `apps/api` is the **composition root**. It wires Postgres, the event bus, metrics and the
     adapters into the packages. `apps/web` consumes only the HTTP API and `@bloody/contracts`.
3. **Modular monolith at runtime.** One API process hosts the control plane, ingest, the
   analytics pipeline and (behind a flag) the scheduler. The seams that let us split it later
   are already interfaces:
   - `EventBus` (in-process today; Kafka topics `bloody.*` later, same contract);
   - `IngestService.prepare()` (a pure function, so a stand-alone ingest tier can reuse it);
   - the scheduler, which runs as its own single-replica Deployment.

   Each future split is an operational decision. None needs a rewrite.
4. **Validation at every boundary with zod.** That covers HTTP bodies and queries, engine
   payloads, configuration (`apps/api/src/config.ts`) and AI tool arguments.
5. **Tests are colocated** (`*.test.ts`, vitest). API integration tests run against a real
   PostgreSQL, never mocks of it.

## Consequences

- One `pnpm -r typecheck` validates every contract consumer, and a breaking contract change fails
  CI everywhere at once.
- Domain packages run in milliseconds in unit tests and are reusable by future workers (ingest,
  detection, AI).
- One deployable keeps operations simple (one image, one migration Job, one HPA). Hot paths
  (ingest, pipeline) scale with the API replicas until they are split.
- Discipline is required: a lint-free import from `apps/*` into a package, or a direct
  `pg`/`fetch` call inside a domain package, would erode the seams. Reviews and the PR checklist
  enforce this.
- CPU-heavy or latency-critical future components (the proprietary endpoint agent, high-volume
  stream processors) may be written in Rust or Go. They would still speak the same contracts,
  generated from the zod schemas as JSON Schema.

## Alternatives considered

- **Microservices from day one.** Rejected: premature seams, distributed transactions across
  tenancy and audit, and N pipelines to secure, scan and release. The interfaces above keep
  that option open.
- **Polyglot core (Go API + TS UI).** Rejected for now: we would duplicate every contract, or
  add a code generator to the critical path. TypeScript gives one type system from the database
  row mapper to the React component.
- **Separate repositories per package.** Rejected: atomic cross-package changes, one lockfile and
  one licence gate matter more than independent versioning at this stage.
- **Nx / Turborepo.** Not needed yet. pnpm's recursive commands with workspace filters cover
  build ordering. Revisit if CI time becomes a problem.
