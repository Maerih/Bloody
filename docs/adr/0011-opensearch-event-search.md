# ADR-0011: OpenSearch as the event search index (Postgres stays the system of record)

- Status: Accepted
- Date: 2026-10-15
- Deciders: Platform architecture

## Context

Event search (`/events/search`, hunting pivots, the AI SOC `search_events` tool) runs on the
partitioned Postgres `events` table. That works for single customers. An MSSP holding months of
endpoint, network and identity telemetry for many customers needs a search engine built for it.
At the same time, detections, correlation, reports and the command center depend on transactional
reads that must not wait for a search index to refresh.

## Decision

- **Postgres stays the system of record.** Ingest writes there first, unchanged.
- **OpenSearch is an index, enabled per installation** with `BLOODY_EVENT_SEARCH=opensearch`.
  - A bus consumer (`SearchIndexer`) mirrors every committed `events.ingested` batch.
  - It inherits the bus guarantees: ordering per tenant, retries, and the Kafka dead-letter topic.
  - Documents are keyed `tenant:event-id`, so indexing is idempotent.
- **Index layout.**
  - Monthly indices `<prefix>-YYYY.MM`, created from one index template.
  - Each document holds the hot columns, derived by the same `eventColumns()` that fills Postgres, plus the whole canonical event as a `flat_object`.
  - `message` uses the `wildcard` field type.
- **Tenant isolation.**
  - Every query is built by `scopedQuery()`, which always adds the caller's tenant (and organization scope) and the time range.
  - Documents are routed by tenant.
- **Same query language, same results.**
  - The Bloody query language and the builder filters compile to OpenSearch DSL from the same parser.
  - A parity test runs the same queries on both stores against a real OpenSearch and requires identical results, counts, pagination and aggregations.
- **Fallback to Postgres.** Postgres answers whenever OpenSearch cannot give an identical result:
  - regular expressions (POSIX vs Lucene dialects);
  - numeric comparison on arbitrary document paths;
  - CIDR on non-IP fields;
  - aggregations on document paths;
  - and whenever OpenSearch is unreachable.
  - Each fallback increments `bloody_event_search_fallbacks_total`.
- **Rebuild.** `search:backfill` re-creates the index from Postgres: on first enablement, after an outage, or after an index loss.

## Consequences

- Search results lag ingest by roughly the refresh interval (1 s). Detections never read the index.
- Storage roughly doubles for retained events. OpenSearch ILM/ISM policies handle index retention.
- OpenSearch (Apache-2.0) runs as an unmodified external service. Bloody talks to it over the REST API with no client library.

## Alternatives rejected

- **OpenSearch as the only event store.** Detections and reports would depend on eventual consistency, and the engine would carry tenancy without row-level security.
- **One index per tenant.** Shard count grows with the number of customers. Shared monthly indices with a mandatory tenant filter scale better for an MSSP.
- **Dynamic mapping of the whole event.** Mappings explode and types conflict across sources. `flat_object` avoids both.
