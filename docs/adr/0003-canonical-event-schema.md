# ADR-0003: Bloody Canonical Event (BCE) schema

- Status: Accepted
- Date: 2026-10-07
- Deciders: Platform architecture, detection engineering

## Context

Telemetry arrives from many engines and sources, each with its own format:

- Wazuh alerts, Zeek logs and Suricata EVE;
- osquery results, Velociraptor collections and OpenCanary events;
- Falco, Trivy, Nuclei and Greenbone output;
- syslog and CEF, cloud audit trails and identity providers.

If detections, correlation, the graph, risk, search, AI and reports consumed vendor formats
directly, every engine upgrade or replacement would ripple through the whole product. That would
destroy the "replaceable engine layer" property (ADR-0004), and the detection content would
become vendor lock-in.

## Decision

1. **One proprietary schema**, `CanonicalEvent` (`packages/contracts/src/event.ts`,
   `BCE_SCHEMA_VERSION = "1.0"`). Each event carries:
   - tenancy: `tenantId`, `organizationId`;
   - `timestamp`, `source` (kind, product, integration, sensor), `category`, `eventType`,
     `action` and `outcome`;
   - typed entity sections: `asset`, `user`, `identity`, `process`, `file`, `network`,
     `cloudResource`;
   - `indicators[]`, `severity` and `risk`, `detection`, `attack[]` (ATT&CK techniques), and
     `labels`;
   - **`provenance`**: adapter, adapter version, `receivedAt`, and `rawRef` or `raw`.
2. **Normalization happens server-side in adapters** (`@bloody/adapters`,
   `normalize(raw) → IngestEvent[]`).
   - Collectors (Vector, the OTel Collector) forward raw vendor records unchanged, tagged only
     with the adapter key as routing key: the ingest API's raw-payload route
     `POST /api/v1/ingest/<adapter>`, or the Kafka topic `bloody.raw.<adapter>`. Producers that
     already emit canonical events use `POST /api/v1/ingest/events`.
   - Adapters can evolve without redeploying collectors on customer sites.
3. **Tenancy is assigned server-side.** `IngestEvent` omits `tenantId`, `organizationId` and
   `schemaVersion`. The ingest service sets them from the authenticated API key or integration,
   never from the payload.
4. **Idempotency.** Adapters derive deterministic event ids from the vendor record and the
   tenant. Storage is `INSERT … ON CONFLICT (tenant_id, id, occurred_at) DO NOTHING`, and only
   newly inserted events are published to the pipeline. Redelivery from collector retries, Kafka
   replays or DLQ re-drives is therefore harmless.
5. **Validation.**
   - Each record is validated individually. Invalid records are rejected with zod issues while
     the rest of the batch is accepted.
   - Events older than `INGEST_MAX_EVENT_AGE_DAYS`, or more than 5 minutes in the future, are
     rejected.
   - Raw records that fail normalization go to a dead-letter path (Vector dead-letter files, or
     Kafka `bloody.dlq`) for replay after an adapter fix. They are never silently dropped.
6. **Storage and transport.**
   - The `events` table is partitioned by month (`ensure_events_partition`). Hot columns are
     extracted for indexing, and the full document is kept as `jsonb`.
   - Large-scale search is an optional `EventStore` backed by OpenSearch.
   - The fabric topics are:
     - `bloody.raw.<adapter>`: raw records;
     - `bloody.events.ingested.v1`: canonical batches, keyed by tenant;
     - `bloody.dlq`.
7. **Versioning.**
   - Additive changes (new optional fields or enum members) are minor and keep `1.x`.
   - Breaking changes bump the major version (`2.0`) with a dual-read window: consumers accept
     both majors, and adapters dual-write during migration.
   - Detection rules reference BCE field paths (`getEventField(event, "process.parent.name")`),
     never vendor fields.

## Consequences

- Detections, correlation, graph upserts, risk, search, AI context and reports are written once,
  against BCE, and work for every current and future source.
- Swapping an engine (for example Suricata for another IDS) means writing one adapter. Nothing
  downstream changes.
- Vendor-specific detail that BCE does not model survives in `labels` and `provenance.raw` or
  object storage (`rawRef`). Forensic fidelity is kept, and analysts can pivot to the raw record.
- Normalization costs CPU on the ingest tier. It scales horizontally with the API, or later with
  a dedicated ingest worker that reuses `IngestService.prepare()`.
- The schema is a long-lived contract. Changes go through review of `packages/contracts`, and
  every contract change is additive by policy.

## Alternatives considered

- **OCSF / ECS as the internal model.** Both are reasonable public schemas, but adopting either
  as the core contract would couple our detection semantics, risk inputs and graph mapping to an
  external committee's roadmap. We would also still need tenancy, provenance and risk
  extensions. BCE stays proprietary, and OCSF/ECS **export** mappings can be added as adapters
  in the other direction.
- **Store raw only and normalize at query time (schema-on-read).** Every query would pay
  normalization, detections could not be precompiled, and per-vendor query logic would leak
  everywhere. Rejected.
- **Normalize in the collectors (VRL/OTTL).** This would put proprietary detection semantics on
  customer-hosted collectors and require redeploying collectors for every mapping fix. Rejected.
