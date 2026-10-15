import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { buildIsolationPolicy, isolationScriptArgs } from "./isolation.js";

const SCRIPT = fileURLToPath(new URL("../../../../infra/agent/active-response/bloody-isolate", import.meta.url));
const run = (args: string[]) => spawnSync("bash", [SCRIPT, "--print", ...args], { encoding: "utf8" });

describe("bloody-isolate (Linux endpoint script)", () => {
  it("renders LAN isolation from exactly the arguments the platform sends", () => {
    const args = isolationScriptArgs(buildIsolationPolicy({ parameters: { mode: "lan", dns: ["9.9.9.9"] } }, ["10.0.0.5"]));
    const out = run(args);
    expect(out.status).toBe(0);
    expect(out.stdout).toContain("set mgmt4 { type ipv4_addr; flags interval; elements = { 10.0.0.5 } }");
    expect(out.stdout).toContain("ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } counter drop");
    // Management is accepted before the local-network drop, and internet falls through to accept.
    const output = out.stdout.slice(out.stdout.indexOf("chain output"));
    expect(output.indexOf("ip daddr @mgmt4 accept")).toBeLessThan(output.indexOf("counter drop"));
    expect(out.stdout).toMatch(/counter drop\n\s+accept\n/);
  });

  it("renders full isolation that drops everything but the management path", () => {
    const out = run(isolationScriptArgs(buildIsolationPolicy({ parameters: { mode: "full" } }, ["203.0.113.10"])));
    expect(out.status).toBe(0);
    expect(out.stdout).toContain("ip daddr @mgmt4 accept");
    expect(out.stdout).not.toMatch(/counter drop\n\s+accept\n/);
  });

  it("refuses unsafe input", () => {
    expect(run(["isolate", "lan", "allow=1.2.3.4;reboot"]).status).not.toBe(0);
    expect(run(["isolate", "full", "allow="]).status).not.toBe(0);
    expect(run(["isolate", "sideways", "allow=1.2.3.4"]).status).not.toBe(0);
  });

  it("accepts the Wazuh JSON message on stdin", () => {
    const out = execFileSync("bash", [SCRIPT, "--print"], { input: JSON.stringify({ version: 1, command: "add", parameters: { extra_args: ["release"] } }) + "\n", encoding: "utf8" });
    expect(out.trim()).toBe("delete table inet bloody_isolation");
  });
});
