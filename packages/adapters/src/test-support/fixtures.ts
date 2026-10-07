import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { IngestEvent } from "@bloody/contracts";
import type { AdapterContext, NormalizedEvent } from "../core/adapter.js";

/** Test-only helpers. Fixtures are authored test data under packages/adapters/fixtures. */

export const FIXTURES_DIR = fileURLToPath(new URL("../../fixtures/", import.meta.url));

export const TENANT_ID = "6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b";
export const INTEGRATION_ID = "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d";
export const RECEIVED_AT = "2026-10-07T12:00:00.000Z";

export function fixtureText(path: string): string {
  return readFileSync(`${FIXTURES_DIR}${path}`, "utf8");
}

export function fixtureBytes(path: string): Uint8Array {
  return new Uint8Array(readFileSync(`${FIXTURES_DIR}${path}`));
}

export function fixtureJson<T = unknown>(path: string): T {
  return JSON.parse(fixtureText(path)) as T;
}

export function ctx(overrides: Partial<AdapterContext> = {}): AdapterContext {
  return { receivedAt: RECEIVED_AT, integrationId: INTEGRATION_ID, ...overrides };
}

/** Every event must round-trip through the contracts' IngestEvent schema unchanged in meaning. */
export function assertSchemaValid(events: readonly NormalizedEvent[]): void {
  for (const e of events) {
    const parsed = IngestEvent.safeParse(e);
    if (!parsed.success) throw new Error(`event ${e.eventType} failed IngestEvent validation: ${parsed.error.message}`);
  }
}

export function byType(events: readonly NormalizedEvent[], eventType: string): NormalizedEvent {
  const e = events.find((x) => x.eventType === eventType);
  if (!e) throw new Error(`no event of type ${eventType}; have: ${events.map((x) => x.eventType).join(", ")}`);
  return e;
}
