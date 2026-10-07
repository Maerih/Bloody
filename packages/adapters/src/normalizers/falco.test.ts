import { describe, expect, it } from "vitest";
import { assertSchemaValid, ctx, fixtureText } from "../test-support/fixtures.js";
import { createFalcoAdapter, falcoPriorityToSeverity } from "./falco.js";

const result = createFalcoAdapter().normalizeDetailed(fixtureText("falco/alerts.jsonl"), ctx());
const [shell, sensitive, c2, k8s] = result.events;

describe("Falco adapter", () => {
  it("maps syscall and k8s_audit alerts; skips non-alerts", () => {
    expect(result.events).toHaveLength(4);
    expect(result.skipped).toHaveLength(1);
    assertSchemaValid(result.events);
  });

  it("terminal shell in container: process, container labels, pod as kubernetes resource", () => {
    expect(shell?.eventType).toBe("falco.syscall");
    expect(shell?.severity).toBe("low");
    expect(shell?.timestamp).toBe("2026-10-07T10:11:12.123Z");
    expect(shell?.process).toMatchObject({ pid: 41233, name: "bash", path: "/usr/bin/bash", commandLine: "bash -i", user: "root", parent: { name: "runc", pid: 41200 } });
    expect(shell?.cloudResource).toEqual({ provider: "kubernetes", resourceType: "pod", resourceId: "prod/payments-api-7d9f8-xk2lp" });
    expect(shell?.labels).toMatchObject({ "container.name": "payments-api", "container.image": "registry.local/payments-api:2.4.1", "k8s.namespace": "prod" });
    expect(shell?.attack).toEqual([{ id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" }]);
    expect(shell?.provenance.raw).toBeDefined();
  });

  it("file access and C2 connection map file / network sub-objects", () => {
    expect(sensitive?.severity).toBe("medium");
    expect(sensitive?.file).toEqual({ path: "/etc/shadow", name: "shadow" });
    expect(c2?.severity).toBe("critical");
    expect(c2?.network).toMatchObject({ srcIp: "10.244.1.12", srcPort: 51515, dstIp: "198.51.100.23", dstPort: 443, direction: "outbound" });
    expect(c2?.indicators).toEqual([{ type: "ip", value: "198.51.100.23" }]);
  });

  it("k8s_audit: cloud category, kubernetes identity, verb and response outcome", () => {
    expect(k8s?.category).toBe("cloud");
    expect(k8s?.identity).toMatchObject({ provider: "kubernetes", principal: "dev-intern", sourceIp: "203.0.113.140" });
    expect(k8s?.cloudResource).toMatchObject({ provider: "kubernetes", resourceType: "pods", resourceId: "prod/payments-api-7d9f8-xk2lp", action: "create" });
    expect(k8s?.outcome).toBe("success");
    expect(k8s?.attack[0]?.id).toBe("T1609");
  });

  it("priority ladder", () => {
    expect(["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"].map(falcoPriorityToSeverity)).toEqual([
      "critical",
      "critical",
      "critical",
      "high",
      "medium",
      "low",
      "info",
      "info",
    ]);
  });
});
