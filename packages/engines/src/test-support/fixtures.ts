/**
 * Test-only fixtures (not exported from the package). Builds valid canonical events with
 * deterministic ids so assertions are stable.
 */
import { CanonicalEvent as CanonicalEventSchema, type CanonicalEvent } from "@bloody/contracts";
import { stableId } from "../util/uuid.js";

export const TENANT_A = "11111111-1111-4111-8111-111111111111";
export const TENANT_B = "22222222-2222-4222-8222-222222222222";
export const ORG_1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
export const ORG_2 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2";
export const BASE_TIME = Date.parse("2026-03-01T10:00:00.000Z");

let counter = 0;

export function at(offsetSeconds: number): string {
  return new Date(BASE_TIME + offsetSeconds * 1000).toISOString();
}

export function makeEvent(partial: Record<string, unknown> & { offsetSeconds?: number } = {}): CanonicalEvent {
  const { offsetSeconds, ...rest } = partial;
  const timestamp = typeof rest.timestamp === "string" ? rest.timestamp : at(offsetSeconds ?? 0);
  return CanonicalEventSchema.parse({
    id: stableId("fixture-event", ++counter),
    tenantId: TENANT_A,
    organizationId: ORG_1,
    source: { kind: "endpoint", product: "test" },
    category: "process",
    eventType: "test",
    provenance: { adapter: "test", adapterVersion: "1", receivedAt: timestamp },
    ...rest,
    timestamp,
  });
}
