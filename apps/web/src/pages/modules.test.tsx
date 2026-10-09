import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { makeMe, makeSummary, ORG_A, TENANT_ID, USER_ID } from "../test/fixtures";
import { getLocation, mockApi, renderApp, type MockHandler, type MockRoute } from "../test/utils";

const EMPTY = { items: [], nextCursor: null };
const NOW = new Date().toISOString();
const LAZY = { timeout: 8000 };

function api(extra: Record<string, MockHandler | MockRoute> = {}) {
  return mockApi({
    "/auth/me": makeMe(),
    "/command-center/summary": makeSummary(),
    "/escalations": EMPTY,
    "/response/actions": EMPTY,
    "/incidents": EMPTY,
    "/alerts": EMPTY,
    "/integrations": [],
    "/users": [],
    ...extra,
  });
}

const EVENT = {
  schemaVersion: "1.0",
  id: "e0000000-0000-4000-8000-000000000001",
  tenantId: TENANT_ID,
  organizationId: ORG_A,
  timestamp: NOW,
  source: { kind: "endpoint", product: "wazuh" },
  category: "process",
  eventType: "process.start",
  message: "powershell.exe -enc SQBFAFgA",
  asset: { hostname: "ws-fin-07" },
  process: { name: "powershell.exe", commandLine: "powershell.exe -enc SQBFAFgA", parent: { name: "winword.exe" } },
  indicators: [],
  severity: "high",
  attack: [{ id: "T1059.001" }],
  labels: {},
  provenance: { adapter: "wazuh", adapterVersion: "1.0.0", receivedAt: NOW },
};

describe("SIEM event search", () => {
  it("runs the builder query against /events/search and opens the event JSON drawer", async () => {
    const { calls } = api({ "/events/search": { items: [EVENT], nextCursor: null, total: 1 } });
    renderApp("/siem/search?q=process.name%3Apowershell.exe&range=24h");
    const builder = await screen.findByTestId("query-builder", {}, LAZY);
    expect(within(builder).getAllByTestId("query-chip")).toHaveLength(1);
    const row = await screen.findByText("ws-fin-07", {}, LAZY);
    const search = calls.find((c) => c.path === "/events/search")!;
    expect(search.url.searchParams.get("q")).toBe("process.name:powershell.exe");
    expect(search.url.searchParams.get("from")).toBeTruthy();
    fireEvent.click(row.closest("tr")!);
    const drawer = await screen.findByRole("dialog", { name: "powershell.exe -enc SQBFAFgA" });
    expect(within(drawer).getByText("Raw canonical event (BCE)")).toBeInTheDocument();
    expect(within(drawer).getAllByText(/"eventType": "process.start"/).length).toBeGreaterThan(0);
  });
});

describe("Module empty states", () => {
  it("shows a real empty state with a Connect <engine> CTA into the Integrations Hub", async () => {
    api({ "/auth/me": makeMe({ entitlements: [{ module: "ndr", state: "active", trialEndsAt: null }] }), "/events/search": EMPTY });
    renderApp("/ndr/dns");
    const connect = await screen.findByRole("link", { name: "Connect Zeek" }, LAZY);
    expect(connect).toHaveAttribute("href", "/integrations?engine=zeek");
    expect(screen.getByRole("heading", { name: "DNS Analytics" })).toBeInTheDocument();
  });

  it("locks modules the tenant is not entitled to", async () => {
    const me = makeMe({ plan: "essentials", entitlements: [{ module: "ndr", state: "locked", trialEndsAt: null }] });
    api({ "/auth/me": me });
    renderApp("/ndr");
    expect(await screen.findByText(/Network Detection & Response is not enabled/, {}, LAZY)).toBeInTheDocument();
  });
});

describe("Vulnerability management", () => {
  it("renders the CVE table with CVSS, EPSS, KEV, SLA and risk-based priority", async () => {
    const vuln = {
      id: "v0000000-0000-4000-8000-000000000001",
      tenantId: TENANT_ID,
      organizationId: ORG_A,
      createdAt: NOW,
      updatedAt: NOW,
      assetId: "a0000000-0000-4000-8000-000000000001",
      assetName: "vpn-gw-01",
      cve: "CVE-2024-3400",
      title: "PAN-OS GlobalProtect command injection",
      cvss: 10,
      epss: 0.957,
      knownExploited: true,
      severity: "critical",
      status: "open",
      patchAvailable: true,
      slaDueAt: new Date(Date.now() - 3 * 86_400_000).toISOString(),
      riskScore: 98,
      priority: "P1",
    };
    const { calls } = api({ "/vulnerabilities": { items: [vuln], nextCursor: null } });
    renderApp("/vulnerabilities?q=CVE-2024");
    const cell = await screen.findByText("CVE-2024-3400", {}, LAZY);
    const row = cell.closest("tr")!;
    expect(row).toHaveTextContent("10.0");
    expect(row).toHaveTextContent("95.7%");
    expect(within(row).getByText("KEV")).toBeInTheDocument();
    expect(within(row).getByText("P1")).toBeInTheDocument();
    expect(row).toHaveTextContent(/3d overdue/);
    expect(calls.find((c) => c.path === "/vulnerabilities")!.url.searchParams.get("q")).toBe("CVE-2024");
    expect(screen.getByRole("heading", { name: "Vulnerabilities" })).toBeInTheDocument();
  });
});

describe("SOAR approvals", () => {
  const action = (over: Record<string, unknown>) => ({
    id: "r0000000-0000-4000-8000-000000000001",
    tenantId: TENANT_ID,
    organizationId: ORG_A,
    incidentId: null,
    action: "isolate_endpoint",
    target: { kind: "asset", id: "a1", label: "ws-fin-07" },
    parameters: {},
    reason: "Encoded PowerShell beaconing to known C2",
    status: "pending_approval",
    requestedBy: "user:someone-else",
    requestedVia: "ai",
    approvedBy: null,
    executor: null,
    result: null,
    createdAt: NOW,
    updatedAt: NOW,
    ...over,
  });

  it("lets a second person approve a high-risk action through the approval gate (never the requester)", async () => {
    const mine = action({ id: "r0000000-0000-4000-8000-000000000002", target: { kind: "asset", id: "a2", label: "db-01" }, requestedBy: `user:${USER_ID}`, requestedVia: "user" });
    const { calls } = api({
      "/response/actions": { items: [action({}), mine], nextCursor: null },
      "POST /response/actions/r0000000-0000-4000-8000-000000000001/approve": action({ status: "approved", approvedBy: USER_ID }),
      "/playbooks": EMPTY,
    });
    renderApp("/soar/approvals");
    const row = (await screen.findAllByText("ws-fin-07", {}, LAZY))[0]!.closest("tr")!;
    expect(within(screen.getAllByText("db-01")[0]!.closest("tr")!).getByText("Requested by you")).toBeInTheDocument();
    fireEvent.click(within(row).getByRole("button", { name: "Approve" }));
    const dialog = await screen.findByRole("dialog", { name: "Approve response action" });
    expect(within(dialog).getByText(/This is a high-risk action/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Approve & execute" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/approve"))).toBe(true));
  });
});

describe("Settings", () => {
  it("creates an API key and shows it exactly once", async () => {
    const created = {
      apiKey: { id: "k1", name: "Vector collector", prefix: "bk_ab12", organizationId: null, roles: [{ role: "api_service", organizationId: null }], createdBy: USER_ID, createdAt: NOW, lastUsedAt: null, lastUsedIp: null, expiresAt: null, revokedAt: null, active: true },
      key: "bk_ab12_s3cr3t-value",
    };
    const { calls } = api({ "/api-keys": [], "POST /api-keys": { status: 201, body: created } });
    renderApp("/settings/api-credentials");
    fireEvent.click((await screen.findAllByRole("button", { name: "Create API key" }, LAZY))[0]!);
    const dialog = await screen.findByRole("dialog", { name: "Create API key" });
    fireEvent.change(within(dialog).getByLabelText(/^Name/), { target: { value: "Vector collector" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create key" }));
    expect(await screen.findByTestId("new-api-key")).toHaveTextContent("bk_ab12_s3cr3t-value");
    expect(calls.find((c) => c.method === "POST" && c.path === "/api-keys")!.body).toEqual({ name: "Vector collector", organizationId: null, roles: ["api_service"], expiresInDays: 90 });
    expect(screen.getByRole("navigation", { name: "Settings" })).toBeInTheDocument();
  });

  it("invites a user with an organization-scoped role", async () => {
    const { calls } = api({ "/teams": [], "POST /users": { status: 201, body: { id: "u2", email: "t1@acme.test", displayName: null } } });
    renderApp("/settings/users");
    fireEvent.click(await screen.findByRole("button", { name: "Invite user" }, LAZY));
    const dialog = await screen.findByRole("dialog", { name: "Invite user" });
    fireEvent.change(within(dialog).getByLabelText(/^E-mail/), { target: { value: "T1@Acme.test" } });
    fireEvent.change(within(dialog).getByLabelText("Scope"), { target: { value: ORG_A } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Grant role" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Invite" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/users")).toBe(true));
    expect(calls.find((c) => c.method === "POST" && c.path === "/users")!.body).toEqual({ email: "t1@acme.test", displayName: null, title: null, organizationId: ORG_A, roles: [{ role: "soc_analyst_t1", organizationId: ORG_A }] });
  });

  it("shows usage meters against plan limits", async () => {
    api({
      "/billing/usage": { limits: { plan: "mssp", limits: { endpoints: 1_000_000 }, overrides: {} }, usage: { endpoints: { used: 1240, limit: 1_000_000, remaining: 998_760, percent: 0.1, resetsAt: null }, aiRequestsPerDay: { used: 120, limit: 500_000, remaining: 499_880, percent: 0, resetsAt: NOW } } },
      "/entitlements": [],
    });
    renderApp("/billing");
    const meters = await screen.findByTestId("usage-meters", {}, LAZY);
    expect(within(meters).getByRole("meter", { name: "Protected endpoints" })).toHaveAttribute("aria-valuenow", "1240");
    expect(within(meters).getByText("AI requests today")).toBeInTheDocument();
  });

  it("filters the audit log from the URL and verifies the hash chain", async () => {
    const record = { id: "au1", seq: 41, at: NOW, organizationId: ORG_A, actor: { kind: "user", id: USER_ID, label: "Test Analyst" }, action: "incident.updated", target: { kind: "incident", id: "i1" }, outcome: "success", ip: "10.0.0.5", userAgent: null, requestId: "req-1", details: { fields: ["status"] }, hash: "abc", prevHash: "def" };
    const { calls } = api({ "/audit": { items: [record], nextCursor: null }, "/audit/verify": { intact: true, firstBrokenSeq: null, records: 41, headSeq: 41, headHash: "abc", verifiedAt: NOW } });
    renderApp("/audit?outcome=success&actor=user");
    expect(await screen.findByText("incident.updated", {}, LAZY)).toBeInTheDocument();
    const q = calls.find((c) => c.path === "/audit")!.url.searchParams;
    expect(q.get("outcome")).toBe("success");
    expect(q.get("actorKind")).toBe("user");
    fireEvent.click(screen.getByRole("button", { name: "Verify integrity" }));
    expect(await screen.findByText(/Hash chain intact across 41 records/)).toBeInTheDocument();
  });
});

describe("Automations", () => {
  it("edits a rule with a {{variable}} preview rendered by the automation engine", async () => {
    const rule = { id: "ru1", tenantId: TENANT_ID, organizationId: null, name: "Critical incidents", event: "incident.created", conditions: [{ field: "severity", op: "eq", value: "critical" }], channelIds: ["c1"], template: { subject: "Incident {{incident.title}}", body: "Open {{link.url}}" }, throttleMinutes: 0, enabled: true };
    const { calls } = api({
      "/automations": [rule],
      "/automations/templates": { items: [] },
      "/notifications/channels": [{ id: "c1", tenantId: TENANT_ID, organizationId: null, name: "SOC on-call", kind: "email", config: { to: ["soc@x.test"] }, enabled: true }],
      "POST /automations/preview": { subject: "Incident ‹incident.title›", text: "Open https://app/incidents/1", missing: [], warnings: [] },
      "PATCH /automations/ru1": ({ body }: { body: unknown }) => ({ ...rule, ...(body as object) }),
    });
    renderApp("/automations");
    fireEvent.click(await screen.findByRole("button", { name: "Edit Critical incidents" }, LAZY));
    const dialog = await screen.findByRole("dialog", { name: "Edit rule: Critical incidents" });
    const preview = within(dialog).getByTestId("template-preview");
    expect(within(preview).getByText(/‹incident\.title›/)).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText(/^Subject/), { target: { value: "Incident {{incident.title}} {{bogus.var}}" } });
    expect(within(dialog).getByText(/Not provided by “Incident created”: \{\{bogus\.var\}\}/)).toBeInTheDocument();
    fireEvent.click(within(preview).getByRole("button", { name: "Render" }));
    expect(await within(preview).findByText("Open https://app/incidents/1")).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText(/^Throttle/), { target: { value: "30" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save rule" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    expect(calls.find((c) => c.method === "PATCH")!.body).toMatchObject({ throttleMinutes: 30, channelIds: ["c1"], template: { subject: "Incident {{incident.title}} {{bogus.var}}" } });
    expect(calls.find((c) => c.method === "POST" && c.path === "/automations/preview")!.body).toMatchObject({ event: "incident.created", organizationId: null });
  });
});

describe("Assets", () => {
  it("lists assets and opens the drill-down drawer with risk explanation and pivots", async () => {
    const asset = { id: "a0000000-0000-4000-8000-0000000000d1", tenantId: TENANT_ID, organizationId: ORG_A, createdAt: NOW, updatedAt: NOW, kind: "domain_controller", name: "dc01", hostname: "dc01.acme.test", ipAddresses: ["10.0.0.10"], os: "Windows Server 2022", criticality: "crown_jewel", internetFacing: false, tags: [], owner: "IT", lastSeenAt: NOW, riskScore: 81 };
    api({
      "/assets": { items: [asset], nextCursor: null },
      [`/assets/${asset.id}`]: { ...asset, agents: [], vulnerabilities: [], alerts: [], incidents: [] },
      [`/risk/assets/${asset.id}`]: { score: 81, severity: "high", likelihood: 0.6, impact: 0.9, summary: "Crown jewel reachable by 2 privileged identities.", modelVersion: "risk/1", factors: [{ key: "asset_criticality", label: "Asset criticality", value: 1, weight: 1, contribution: 30, explanation: "Domain controller" }] },
      "/graph/search": [],
      "/attack-paths": { paths: [], remediations: [], summary: { totalPaths: 0 } },
    });
    renderApp(`/assets?id=${asset.id}`);
    const drawer = await screen.findByRole("dialog", { name: "dc01.acme.test" }, LAZY);
    expect(await within(drawer).findByText("Crown jewel reachable by 2 privileged identities.")).toBeInTheDocument();
    expect(within(drawer).getByRole("link", { name: "Graph pivot" })).toHaveAttribute("href", "/graph?q=dc01.acme.test");
    expect(within(drawer).getByText("No discovered attack path runs through this asset.")).toBeInTheDocument();
    fireEvent.click(within(drawer).getByRole("button", { name: /Close/ }));
    await waitFor(() => expect(getLocation().search).not.toContain("id="));
  });
});

describe("Threat intelligence", () => {
  it("rolls indicators up into threat actors with environment matches", async () => {
    const ind = (id: string, value: string, actor: string, severity: string) => ({ id, tenantId: TENANT_ID, organizationId: null, type: "ip", value, confidence: 80, severity, source: "misp", threatActor: actor, malware: "Cobalt Strike", campaign: null, tags: [], firstSeenAt: NOW, lastSeenAt: NOW, expiresAt: null });
    api({
      "/intel/indicators": { items: [ind("i1", "203.0.113.10", "FIN7", "high"), ind("i2", "203.0.113.11", "FIN7", "critical"), ind("i3", "198.51.100.5", "APT29", "medium")], nextCursor: null },
      "/intel/matches": { items: [{ id: "m1", indicatorId: "i2", organizationId: ORG_A, matchedAt: NOW, entityKind: "asset", entityId: "a1", entityLabel: "ws-fin-07" }], nextCursor: null },
    });
    renderApp("/intel/actors");
    const fin7 = (await screen.findByText("FIN7", {}, LAZY)).closest("tr")!;
    expect(fin7).toHaveTextContent("1 match(es) · 1 IOC(s)");
    expect(within(fin7).getByText("Cobalt Strike")).toBeInTheDocument();
    fireEvent.click(fin7);
    expect(await screen.findByText("203.0.113.11")).toBeInTheDocument();
    expect(screen.queryByText("198.51.100.5")).not.toBeInTheDocument();
  });
});

describe("Integrations Hub", () => {
  it("groups the engine catalogue by layer with licence risk and configures a connection", async () => {
    const { calls } = api({ "POST /integrations": { status: 201, body: { id: "int1", engine: "zeek", name: "Zeek", organizationId: null, endpoint: null, enabled: true, hasCredential: false, status: "pending", lastSyncAt: null, lastError: null } } });
    renderApp("/hub/engines");
    const network = await screen.findByRole("region", { name: "Network" }, LAZY);
    const zeek = within(network).getByRole("article", { name: "Zeek" });
    expect(within(zeek).getByText("BSD-3-Clause")).toBeInTheDocument();
    expect(within(zeek).getByText("licence risk: low")).toBeInTheDocument();
    expect(within(screen.getByRole("article", { name: "Wazuh" })).getByText("licence risk: medium")).toBeInTheDocument();
    fireEvent.click(within(zeek).getByRole("button", { name: "Connect Zeek" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: /Save|Connect|Add/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/integrations")).toBe(true));
    expect(calls.find((c) => c.method === "POST" && c.path === "/integrations")!.body).toMatchObject({ engine: "zeek", enabled: true });
  });
});

describe("AI SOC", () => {
  const INC = "22222222-2222-4222-8222-222222222222";
  const CONV = "c0000000-0000-4000-8000-000000000001";
  const provider = { id: "p1", tenantId: TENANT_ID, organizationId: null, name: "Local Llama", kind: "ollama", endpoint: "http://localhost:11434", model: "llama3.1:8b", credentialRef: null, hasCredential: false, contextWindow: 32768, temperature: 0.2, maxOutputTokens: 2048, systemPolicy: null, maxToolTier: "recommend", isDefault: true, fallbackProviderId: null, retentionDays: 30, redactSensitive: true, allowCloudData: false, enabled: true, createdAt: NOW, updatedAt: NOW };

  it("binds the thread to ?context=, shows tool calls with tier badges and gates actions behind approval", async () => {
    const { calls } = api({
      "/ai/providers": [provider],
      "/ai/conversations": { items: [{ id: CONV, title: "Credential dumping triage", organizationId: ORG_A, context: { kind: "incident", id: INC }, createdAt: NOW, updatedAt: NOW }] },
      [`/ai/conversations/${CONV}`]: {
        conversation: { id: CONV, title: "Credential dumping triage", organizationId: ORG_A, context: { kind: "incident", id: INC }, createdAt: NOW, updatedAt: NOW },
        messages: [
          { seq: 1, at: NOW, message: { role: "user", content: "Contain the affected host" } },
          { seq: 2, at: NOW, message: { role: "assistant", content: "", toolCalls: [{ id: "t1", name: "search_events", arguments: { q: "asset.hostname:dc01" } }, { id: "t2", name: "isolate_endpoint", arguments: { assetId: "a1" } }] } },
          { seq: 3, at: NOW, message: { role: "assistant", content: "I searched the host's events and requested isolation; it needs approval." } },
        ],
        actions: [
          { id: "x1", conversationId: CONV, tool: "search_events", tier: "investigate", arguments: {}, status: "completed", result: { hits: 3 }, requestedBy: "ai:p1", approvedBy: null, at: NOW },
          { id: "x2", conversationId: CONV, tool: "isolate_endpoint", tier: "require_approval", arguments: {}, status: "pending_approval", result: null, requestedBy: "ai:p1", approvedBy: null, at: NOW },
        ],
      },
      [`/incidents/${INC}`]: { id: INC, tenantId: TENANT_ID, organizationId: ORG_A, number: 42, title: "Credential dumping on DC01", summary: null, severity: "critical", status: "investigating", riskScore: 91, assigneeId: null, attack: [], alertCount: 1, assetIds: [], identityIds: [], detectedAt: NOW, acknowledgedAt: null, containedAt: null, closedAt: null, createdAt: NOW, updatedAt: NOW },
      "POST /ai/actions/x2/approve": { id: "x2", status: "approved" },
    });
    renderApp(`/ai?context=incident:${INC}&c=${CONV}`);
    const chip = await screen.findByTestId("ai-context-chip", {}, LAZY);
    await waitFor(() => expect(chip).toHaveTextContent("Incident #42 Credential dumping on DC01"));
    const toolCalls = await screen.findAllByTestId("ai-tool-call");
    expect(toolCalls).toHaveLength(2);
    expect(within(toolCalls[0]!).getByText("INVESTIGATE")).toBeInTheDocument();
    expect(within(toolCalls[1]!).getByText("REQUIRE APPROVAL")).toBeInTheDocument();
    expect(within(toolCalls[1]!).getByText(/Nothing runs until a human approves it/)).toBeInTheDocument();
    expect(screen.getByLabelText("Model")).toHaveValue("p1");
    fireEvent.click(within(toolCalls[1]!).getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/ai/actions/x2/approve")).toBe(true));
  });
});

describe("Investigation workspace", () => {
  const INV = "f0000000-0000-4000-8000-000000000001";
  const SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
  const investigation = {
    id: INV,
    tenantId: TENANT_ID,
    organizationId: ORG_A,
    createdAt: NOW,
    updatedAt: NOW,
    incidentId: null,
    title: "Suspicious OAuth consent at Acme",
    status: "in_progress",
    leadId: USER_ID,
    hypothesis: "A phished user consented to a malicious app.",
    closedAt: null,
    timeline: [{ id: "t1", investigationId: INV, kind: "note", at: NOW, actorId: `user:${USER_ID}`, title: "Investigation opened", body: null, refId: null }],
    notes: [],
    tasks: [],
    evidence: [
      {
        id: "ev1",
        tenantId: TENANT_ID,
        organizationId: ORG_A,
        createdAt: NOW,
        updatedAt: NOW,
        investigationId: INV,
        name: "consent-audit.json",
        kind: "log_export",
        sha256: SHA,
        sizeBytes: 2048,
        storageRef: "s3://evidence/t/o/ev1",
        tags: [],
        collectedBy: `user:${USER_ID}`,
        custody: [{ at: NOW, actor: `user:${USER_ID}`, action: "collected", hash: "h1" }],
        custodyVerification: { valid: true, brokenAt: null },
      },
    ],
  };

  it("shows evidence with SHA-256 and chain of custody, and adds a note", async () => {
    const { calls } = api({
      [`/investigations/${INV}`]: investigation,
      [`POST /investigations/${INV}/notes`]: { status: 201, body: { id: "n1", organizationId: ORG_A, incidentId: null, investigationId: INV, authorId: USER_ID, authorLabel: null, body: "Revoked the app's tokens", visibility: "internal", createdAt: NOW } },
      "/ai/providers": [],
    });
    renderApp(`/investigations/${INV}?tab=evidence`);
    const list = await screen.findByTestId("evidence-list", {}, LAZY);
    expect(within(list).getByText("consent-audit.json")).toBeInTheDocument();
    expect(within(list).getByText(SHA)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: /Chain of custody/ }));
    const custody = await screen.findByTestId("custody-panel");
    expect(within(custody).getByLabelText("Verified link")).toBeInTheDocument();
    for (const tab of ["Timeline", "Alerts", "Entities", "Graph", "Process tree", "Network", "Identity events", "Threat intel", "Tasks", "Collaborators", "Response"]) {
      expect(screen.getByRole("tab", { name: new RegExp(tab) })).toBeInTheDocument();
    }
    fireEvent.click(screen.getByRole("tab", { name: /Notes/ }));
    fireEvent.change(await screen.findByLabelText("Note"), { target: { value: "Revoked the app's tokens" } });
    fireEvent.click(screen.getByRole("button", { name: /Add note/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === `/investigations/${INV}/notes`)).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ body: "Revoked the app's tokens", visibility: "internal" });
  });
});
