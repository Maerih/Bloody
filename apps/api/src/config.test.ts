import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig } from "./config.js";

const KEY = Buffer.alloc(32, 1).toString("base64");
const PROD = { NODE_ENV: "production", JWT_SECRET: "p".repeat(40), ENCRYPTION_KEY: KEY, PUBLIC_URL: "https://soc.example.com" };

describe("loadConfig", () => {
  it("uses safe development defaults and says so", () => {
    const c = loadConfig({});
    expect(c.env).toBe("development");
    expect(c.port).toBe(4000);
    expect(c.database.privilegedUrl).toBe("postgres://postgres:postgres@localhost:5432/bloody");
    expect(c.database.appUrl).toBe("postgres://bloody_app:bloody_app@localhost:5432/bloody");
    expect(c.auth.accessTokenTtlSeconds).toBe(900);
    expect(c.http.cookieSecure).toBe(true);
    expect(c.http.corsOrigins).toContain("http://localhost:5173");
    expect(c.warnings.join(" ")).toMatch(/JWT_SECRET not set/);
    expect(c.warnings.join(" ")).toMatch(/ENCRYPTION_KEY not set/);
    expect(c.smtp).toBeNull();
    expect(c.oidc).toBeNull();
    expect(Object.isFrozen(c)).toBe(true);
  });

  it("requires real secrets in production", () => {
    expect(() => loadConfig({ ...PROD, JWT_SECRET: undefined })).toThrow(/JWT_SECRET is required/);
    expect(() => loadConfig({ ...PROD, JWT_SECRET: "short" })).toThrow(/at least 32/);
    expect(() => loadConfig({ ...PROD, ENCRYPTION_KEY: undefined })).toThrow(/ENCRYPTION_KEY/);
    expect(() => loadConfig({ ...PROD, ENCRYPTION_KEY: Buffer.alloc(16).toString("base64") })).toThrow(/32 bytes/);
    const c = loadConfig(PROD);
    expect(c.warnings).toEqual(["DATABASE_APP_URL not set — derived from DATABASE_URL with role bloody_app"]);
    expect(c.http.corsOrigins).toEqual(["https://soc.example.com"]);
  });

  it("validates values and the CORS allow-list", () => {
    expect(() => loadConfig({ PORT: "99999" })).toThrow(ConfigError);
    expect(() => loadConfig({ NODE_ENV: "staging" })).toThrow(/NODE_ENV/);
    expect(() => loadConfig({ CORS_ORIGINS: "*" })).toThrow(/explicit allow-list/);
    expect(loadConfig({ CORS_ORIGINS: "https://a.example, https://b.example" }).http.corsOrigins).toEqual(["https://a.example", "https://b.example"]);
    expect(loadConfig({ COOKIE_SECURE: "false" }).http.cookieSecure).toBe(false);
  });

  it("accepts BLOODY_-prefixed aliases, key versions and SMTP / OIDC settings", () => {
    const old = Buffer.alloc(32, 2).toString("base64");
    const c = loadConfig({
      BLOODY_JWT_SECRET: "a".repeat(40),
      BLOODY_ENCRYPTION_KEY: KEY,
      ENCRYPTION_KEY_VERSION: "3",
      ENCRYPTION_PREVIOUS_KEYS: `1:${old},2:${old}`,
      SMTP_HOST: "smtp.example.com",
      SMTP_USER: "bloody",
      OIDC_ISSUER_URL: "https://idp.example.com/realms/bloody/",
      OIDC_CLIENT_ID: "bloody-web",
      PUBLIC_URL: "https://soc.example.com",
      DATABASE_APP_URL: "postgres://bloody_app:secret@db:5432/bloody",
      "": "",
    });
    expect(new TextDecoder().decode(c.auth.jwtSecret)).toBe("a".repeat(40));
    expect([...c.encryption.keys.keys()].sort()).toEqual([1, 2, 3]);
    expect(c.encryption.activeVersion).toBe(3);
    expect(c.smtp).toMatchObject({ host: "smtp.example.com", port: 587, user: "bloody", from: "notifications@bloody.local" });
    expect(c.oidc).toMatchObject({ issuerUrl: "https://idp.example.com/realms/bloody", redirectUri: "https://soc.example.com/api/v1/auth/oidc/callback", scopes: "openid email profile" });
    expect(c.database.appUrl).toBe("postgres://bloody_app:secret@db:5432/bloody");
    expect(() => loadConfig({ ENCRYPTION_PREVIOUS_KEYS: "bad" })).toThrow(/<version>:<base64>/);
    expect(() => loadConfig({ ...PROD, OIDC_ISSUER_URL: "http://idp.example.com", OIDC_CLIENT_ID: "x" })).toThrow(/https/);
  });
});
