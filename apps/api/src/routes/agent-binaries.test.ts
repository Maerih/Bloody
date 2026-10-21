import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, call, createTenant, createTestApp, login, type TestApp } from "../test/harness.js";

let t: TestApp;
let admin: ReturnType<typeof api>;
const dir = mkdtempSync(path.join(tmpdir(), "sciat-bin-"));
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const linux = Buffer.from("\x7fELF fake linux binary");
const windows = Buffer.from("MZ fake windows binary");

beforeAll(async () => {
  writeFileSync(path.join(dir, "sciat-agent-linux-amd64"), linux);
  writeFileSync(path.join(dir, "sciat-agent-windows-amd64.exe"), windows);
  writeFileSync(path.join(dir, "secret.txt"), "not served");
  writeFileSync(path.join(dir, "VERSION"), "2.0.0\n");
  writeFileSync(
    path.join(dir, "SHA256SUMS"),
    [`${sha(linux)}  sciat-agent-linux-amd64`, `${sha(windows)}  sciat-agent-windows-amd64.exe`, `${sha(Buffer.from("x"))}  secret.txt`, `${sha(Buffer.from("y"))}  sciat-agent-linux-arm64`].join("\n") + "\n",
  );
  t = await createTestApp({ env: { BLOODY_AGENT_BINARIES_DIR: dir } });
  const tenant = await createTenant(t, { orgs: 1 });
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
});
afterAll(async () => {
  await t?.close();
});

describe("native agent binaries", () => {
  it("lists the binaries in SHA256SUMS that exist, with their checksums", async () => {
    const res = await admin.get("/agents/native");
    expect(res.status).toBe(200);
    expect(res.body.release).toEqual({
      version: "2.0.0",
      files: [
        { name: "sciat-agent-linux-amd64", os: "linux", arch: "amd64", sha256: sha(linux), size: linux.length },
        { name: "sciat-agent-windows-amd64.exe", os: "windows", arch: "amd64", sha256: sha(windows), size: windows.length },
      ],
    });
    expect((await call(t.app, "GET", "/agents/native")).status).toBe(401);
  });

  it("serves a binary to endpoints without signing in, and nothing else", async () => {
    const res = await t.app.inject({ method: "GET", url: "/api/v1/agent/download/sciat-agent-windows-amd64.exe" });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toBe("application/octet-stream");
    expect(res.headers["x-content-sha256"]).toBe(sha(windows));
    expect(res.rawPayload.equals(windows)).toBe(true);
    for (const name of ["secret.txt", "SHA256SUMS", "sciat-agent-linux-arm64", "..%2FVERSION", "sciat-agent-linux-amd64%2F..%2Fsecret.txt"]) {
      const r = await t.app.inject({ method: "GET", url: `/api/v1/agent/download/${name}` });
      expect([400, 404], name).toContain(r.statusCode);
    }
  });
});
