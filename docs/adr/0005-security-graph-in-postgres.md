# ADR-0005: Security Graph stored in PostgreSQL first

- Status: Accepted
- Date: 2026-10-07
- Deciders: Platform architecture, detection engineering

## Context

The Security Graph is the core of Bloody's correlation, exposure and attack-path analysis. It
links organizations, users and identities, groups, endpoints and servers, cloud assets,
processes, files and hashes, IPs and domains, vulnerabilities, credentials, sessions, indicators,
threat actors, incidents and ATT&CK techniques (`NODE_KINDS` / `EDGE_KINDS` in
`packages/contracts/src/graph.ts`).

The graph must be:

- **tenant-isolated with the same guarantees as every other table** (ADR-0002);
- **transactional with the rest of the domain**: an incident, its alerts and its graph edges are
  written together;
- **queryable for bounded neighbourhoods** (pivoting in the UI, 1–3 hops) and for **attack-path
  search** to crown jewels (6–8 hops, weighted);
- **licence-clean** for proprietary SaaS (ADR-0004 rules out Neo4j Community/GPL and BSL graph
  databases);
- **cheap to operate** at the start: one database to back up, restore and secure.

## Decision

1. **Storage.** Two Postgres tables, `graph_nodes` and `graph_edges`
   (`apps/api/migrations/0006_graph.sql`), with `tenant_id` + `organization_id`, RLS like every
   tenant table, and `props jsonb` (GIN-indexed).
   - Nodes have a natural key unique per `(tenant, org, kind, key)` (hostname, sha256, IP, CVE,
     principal…). Upserts are therefore idempotent, and entity resolution converges.
   - Edges are unique per `(tenant, from, kind, to)` and indexed both ways for traversal.
   - Composite foreign keys keep edges inside one tenant.
2. **Storage behind an interface.** `@bloody/engines` defines `SqlGraphStore`, plus an
   `InMemoryGraphStore` for tests. `apps/api/src/graph/postgres-store.ts` implements it.
   Traversal (`traverseNeighbors`) is bounded (depth, fan-out and result limits) so a hub node
   such as `internet` or a domain controller cannot explode a query.
3. **Analytics run in the engines package, not in SQL.** The Attack-Path Engine loads a bounded,
   tenant-scoped subgraph and computes weighted paths and minimal-cut remediations in memory.
   Every path carries a `RiskAssessment` with `RiskFactor[]` (ADR-0006). Results are cached per
   tenant (`AttackPathService`, 60 s TTL).
4. **Write path.** The analytics pipeline upserts nodes and edges from canonical events (asset,
   identity, process, network, indicator sections) before detection and risk. Writes are
   idempotent, so pipeline retries are safe.

## Consequences

- One transactional store and one backup/PITR story. RLS covers the graph automatically, and
  `pg_dump` is the full state.
- Neighbourhood queries are index lookups. Deep multi-hop queries are done in memory over
  bounded subgraphs, which is fast at the expected per-tenant sizes (≈10⁵–10⁶ edges per large
  enterprise).
- The `SqlGraphStore` seam lets us move to a dedicated graph engine without touching detection,
  risk or UI code.
- **Revisit triggers** (any one, sustained):
  - more than 50 M edges in one tenant;
  - p95 1-hop neighbour query above 200 ms;
  - attack-path computation above 5 s on the bounded subgraph;
  - product need for ad-hoc graph query languages (Cypher/GQL) exposed to customers.

  Candidates, in order: Apache AGE (Apache-2.0, Postgres extension, which keeps the single
  store), JanusGraph (Apache-2.0), or a proprietary store. Neo4j and BSL engines remain
  excluded by ADR-0004.

## Alternatives considered

- **Neo4j.** Community is GPL-3.0, with limited clustering and no fine-grained multi-tenancy.
  Enterprise is commercially licensed. Rejected on licence and isolation grounds.
- **Memgraph or other BSL graph databases.** Excluded by the licence gate (BSL).
- **Amazon Neptune or Azure Cosmos Gremlin.** Cloud lock-in, no customer-hosted or air-gapped
  story, and a second isolation model to secure. Rejected for the core. A Neptune *adapter*
  remains possible for single-cloud customers.
- **Recursive CTEs for everything.** Fine for 1–3 hops. For weighted path search with pruning,
  explicit algorithms in TypeScript are clearer, testable and explainable.
