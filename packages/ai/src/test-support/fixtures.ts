import type { AiProviderConfig, Principal, RoleKey } from "@bloody/contracts";
import type { Clock } from "../util/ids.js";

/** Test fixtures only — never imported by production code. */

export const TENANT_A = "11111111-1111-4111-8111-111111111111";
export const TENANT_B = "22222222-2222-4222-8222-222222222222";
export const ORG_A1 = "aaaaaaa1-0000-4000-8000-000000000001";
export const ORG_A2 = "aaaaaaa2-0000-4000-8000-000000000002";
export const ORG_B1 = "bbbbbbb1-0000-4000-8000-000000000001";

export function principal(role: RoleKey, opts: { id?: string; tenantId?: string; organizationId?: string | null } = {}): Principal {
  return {
    kind: "user",
    id: opts.id ?? `user-${role}`,
    tenantId: opts.tenantId ?? TENANT_A,
    email: `${role}@example.test`,
    bindings: [{ role, organizationId: opts.organizationId === undefined ? ORG_A1 : opts.organizationId }],
  };
}

let seq = 0;
export function providerConfig(overrides: Partial<AiProviderConfig> = {}): AiProviderConfig {
  seq += 1;
  const n = String(seq).padStart(12, "0");
  return {
    id: `cccccccc-0000-4000-8000-${n}`,
    tenantId: TENANT_A,
    organizationId: null,
    name: `provider-${seq}`,
    kind: "openai",
    endpoint: null,
    model: "gpt-test",
    credentialRef: "secret://test",
    hasCredential: true,
    contextWindow: 32_768,
    temperature: 0.2,
    maxOutputTokens: 1024,
    systemPolicy: null,
    maxToolTier: "recommend",
    isDefault: false,
    fallbackProviderId: null,
    retentionDays: 30,
    redactSensitive: true,
    allowCloudData: true,
    enabled: true,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

export class FixedClock implements Clock {
  constructor(private current: Date = new Date("2026-10-07T12:00:00.000Z")) {}
  now(): Date {
    return new Date(this.current);
  }
  advance(ms: number): void {
    this.current = new Date(this.current.getTime() + ms);
  }
}

export function sequentialIds(prefix = "00000000-0000-4000-8000-"): () => string {
  let n = 0;
  return () => `${prefix}${String(++n).padStart(12, "0")}`;
}

export const noSleep = async (): Promise<void> => undefined;
