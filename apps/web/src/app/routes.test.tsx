import { describe, expect, it } from "vitest";
import { activeRailModule, allNavPaths, findNavMatch, RAIL_MODULES } from "./navigation";
import { buildAppRoutes, CORE_ROUTES } from "./routes";

describe("route table", () => {
  it("covers every navigable path so navigation never 404s", () => {
    const routes = buildAppRoutes([]);
    const paths = new Set(routes.map((r) => r.path));
    for (const p of allNavPaths()) expect(paths.has(p)).toBe(true);
    expect(paths.has("/assets/*")).toBe(true);
    expect(routes.length).toBe(paths.size);
  });

  it("lets module routes replace placeholders", () => {
    const routes = buildAppRoutes([{ path: "/reports", element: null }]);
    expect(routes.filter((r) => r.path === "/reports")).toHaveLength(1);
    expect(routes.find((r) => r.path === "/reports")!.element).toBeNull();
    expect(CORE_ROUTES.some((r) => r.path === "/")).toBe(true);
  });

  it("defines a flyout for every rail module, each with sub-pages", () => {
    const shorts = RAIL_MODULES.map((m) => m.short);
    expect(shorts).toEqual(["Home", "EDR", "ITDR", "NDR", "SIEM", "XDR", "ASM", "ESPM", "ISPM", "CSPM", "CIEM", "SSPM", "VM", "K8S", "CTI", "DFIR", "SOAR", "MAIL", "DECOY", "AI", "Trials", "Hub"]);
    for (const m of RAIL_MODULES) expect(m.items.length).toBeGreaterThan(1);
    const edr = RAIL_MODULES.find((m) => m.id === "edr")!;
    expect(edr.items.map((i) => i.label)).toEqual(expect.arrayContaining(["EDR Dashboard", "Persistent Footholds", "Process Insights", "Managed Antivirus", "Ransomware Canaries", "External Recon"]));
  });

  it("matches paths to modules", () => {
    expect(activeRailModule("/edr/processes")?.id).toBe("edr");
    expect(activeRailModule("/mssp")?.id).toBe("home");
    expect(findNavMatch("/soar/channels").item?.label).toBe("Notification Channels");
    expect(findNavMatch("/assets/123").item?.label).toBe("Assets");
  });
});
