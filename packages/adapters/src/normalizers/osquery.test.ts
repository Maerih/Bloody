import { describe, expect, it } from "vitest";
import { assertSchemaValid, ctx, fixtureText } from "../test-support/fixtures.js";
import { createOsqueryAdapter, osqueryCategory } from "./osquery.js";

const adapter = createOsqueryAdapter();
const result = adapter.normalizeDetailed(fixtureText("osquery/results.jsonl"), ctx());

describe("osquery adapter", () => {
  it("expands differential, batched differential and snapshot results into one event per row", () => {
    expect(result.events).toHaveLength(8);
    expect(result.skipped).toEqual([{ index: 5, reason: "empty snapshot" }]);
    assertSchemaValid(result.events);
  });

  it("process differential: process fields, decorations → asset, unixTime → timestamp", () => {
    const e = result.events[0];
    expect(e?.category).toBe("process");
    expect(e?.timestamp).toBe("2026-10-07T10:20:00.000Z");
    expect(e?.action).toBe("added");
    expect(e?.asset).toEqual({ hostname: "lnx-db-01", agentId: "4C4C4544-0042-3510-8051-B4C04F4E3732", os: "Ubuntu" });
    expect(e?.process).toMatchObject({ pid: 31337, path: "/tmp/.x/kworker", commandLine: expect.stringContaining("4444"), user: "www-data", parent: { pid: 1022 } });
    expect(e?.labels["osquery.pack"]).toBe("bloody");
    expect(e?.labels["osquery.col.cmdline"]).toContain("kworker");
  });

  it("diffResults produce added and removed events; snapshot rows are distinct events", () => {
    const ports = result.events.filter((e) => e.eventType === "osquery.pack_bloody_listening_ports");
    expect(ports.map((e) => e.action)).toEqual(["added", "removed"]);
    expect(ports[0]?.network).toMatchObject({ srcPort: 4444, protocol: "tcp" });
    const users = result.events.filter((e) => e.action === "snapshot");
    expect(users).toHaveLength(3);
    expect(new Set(users.map((u) => u.labels["dedup_key"])).size).toBe(3);
  });

  it("file_events and socket events", () => {
    const file = result.events.find((e) => e.eventType === "osquery.file_events");
    expect(file?.file).toMatchObject({ path: "/etc/cron.d/persist", action: "create", size: 112 });
    const sock = result.events.find((e) => e.eventType === "osquery.pack_bloody_socket_events");
    expect(sock?.network).toMatchObject({ srcIp: "10.0.5.10", dstIp: "198.51.100.23", dstPort: 4444, direction: "outbound" });
    expect(sock?.indicators).toEqual([{ type: "ip", value: "198.51.100.23" }]);
  });

  it("category inference and snapshot row cap", () => {
    expect(osqueryCategory("pack_x_logged_in_users", {})).toBe("authentication");
    expect(osqueryCategory("windows_registry_run", {})).toBe("registry");
    expect(osqueryCategory("deb_packages", { name: "x" })).toBe("configuration");
    const capped = adapter.normalize(fixtureText("osquery/results.jsonl"), ctx({ options: { maxRowsPerSnapshot: 1 } }));
    expect(capped.filter((e) => e.action === "snapshot")).toHaveLength(1);
  });
});
