import { describe, expect, it } from "vitest";
import { RMM_TOOLS, detectRmmTools } from "./rmm-guard.js";

describe("RMM Guard", () => {
  it("finds remote-access tools from processes and installed software", () => {
    const found = detectRmmTools({
      software: [{ name: "AnyDesk", version: "8.0.14" }, { name: "Google Chrome" }, { name: "ScreenConnect Client (a1b2c3)" }],
      processes: [
        { name: "AnyDesk.exe", path: "C:\\Users\\amina\\Downloads\\AnyDesk.exe" },
        { name: "ScreenConnect.ClientService.exe", path: "C:\\Program Files (x86)\\ScreenConnect Client (a1b2c3)\\ScreenConnect.ClientService.exe" },
        { name: "chrome.exe", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" },
        { name: "meshagent" },
      ],
    });
    expect([...found.keys()].sort()).toEqual(["anydesk", "meshcentral", "screenconnect"]);
    expect(found.get("anydesk")).toEqual([
      { kind: "process", value: "C:\\Users\\amina\\Downloads\\AnyDesk.exe" },
      { kind: "software", value: "AnyDesk 8.0.14" },
    ]);
  });

  it("does not flag ordinary software", () => {
    expect(detectRmmTools({ software: [{ name: "Microsoft Teams" }, { name: "Zoom" }], processes: [{ name: "svchost.exe" }, { name: "agent.exe" }] }).size).toBe(0);
  });

  it("has unique keys and something to match for every tool", () => {
    expect(new Set(RMM_TOOLS.map((t) => t.key)).size).toBe(RMM_TOOLS.length);
    for (const t of RMM_TOOLS) expect(t.processes.length + t.software.length).toBeGreaterThan(0);
  });
});
