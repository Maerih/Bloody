import { describe, expect, it } from "vitest";
import { assertSchemaValid, ctx, fixtureText } from "../test-support/fixtures.js";
import { createKeycloakAdapter } from "./keycloak.js";

const adapter = createKeycloakAdapter();

describe("Keycloak adapter — login events", () => {
  const events = adapter.normalize(fixtureText("keycloak/events.json"), ctx());
  const [login, loginError, removeTotp, impersonate, clientLogin] = events;

  it("maps every event with epoch-ms timestamps and validates", () => {
    expect(events).toHaveLength(5);
    expect(login?.timestamp).toBe("2026-10-07T10:46:40.000Z");
    assertSchemaValid(events);
  });

  it("successful and failed logins carry identity, outcome and source IP", () => {
    expect(login?.identity).toEqual({ provider: "keycloak:acme", principal: "alice@acme.example", sourceIp: "198.51.100.7", outcome: "success" });
    expect(login?.source.kind).toBe("identity");
    expect(loginError?.outcome).toBe("failure");
    expect(loginError?.severity).toBe("low");
    expect(loginError?.labels["keycloak.error"]).toBe("invalid_user_credentials");
    expect(loginError?.attack[0]?.id).toBe("T1110");
    expect(JSON.stringify(loginError?.provenance.raw)).not.toContain("should-never-be-here");
  });

  it("MFA removal and impersonation are ITDR signals", () => {
    expect(removeTotp?.severity).toBe("medium");
    expect(removeTotp?.attack[0]).toEqual({ id: "T1556.006", name: "Multi-Factor Authentication", tactic: "Persistence" });
    expect(impersonate?.severity).toBe("high");
    expect(clientLogin?.identity?.principal).toBe("svc-reporting");
    expect(clientLogin?.labels["dedup_key"]).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe("Keycloak adapter — admin events", () => {
  const events = adapter.normalize(fixtureText("keycloak/admin-events.json"), ctx());
  const [roleGrant, idp, userCreate] = events;

  it("admin role grants are high severity with role names, never the representation", () => {
    expect(roleGrant?.eventType).toBe("keycloak.admin.realm_role_mapping.create");
    expect(roleGrant?.severity).toBe("high");
    expect(roleGrant?.labels["keycloak.roles"]).toBe("realm-admin");
    expect(roleGrant?.user).toEqual({ name: "u-mallory" });
    expect(roleGrant?.identity).toMatchObject({ principal: "u-admin", privileged: true });
    assertSchemaValid(events);
  });

  it("identity-provider changes and user creation; secrets in representations are not stored", () => {
    expect(idp?.severity).toBe("high");
    expect(idp?.attack[0]?.id).toBe("T1484");
    expect(userCreate?.attack[0]?.id).toBe("T1136");
    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain("super-secret");
    expect(serialized).not.toContain("P@ss");
  });
});
