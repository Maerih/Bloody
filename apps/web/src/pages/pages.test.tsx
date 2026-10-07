import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { makeMe, makeMsspOverview, makeSummary, ORG_A, TENANT_ID } from "../test/fixtures";
import { getLocation, mockApi, renderApp } from "../test/utils";
import { coerceConditionValue } from "./automation/AutomationRulesPage";
import { isSafeWebhookUrl, parseRecipients } from "./automation/NotificationChannelsPage";
import { parseSeverityParam, parseStatusParam } from "./incidents/IncidentsPage";

const EMPTY = { items: [], nextCursor: null };
const now = new Date().toISOString();

const INCIDENT = {
  id: "22222222-2222-4222-8222-222222222222",
  tenantId: TENANT_ID,
  organizationId: ORG_A,
  number: 42,
  title: "Credential dumping on DC01",
  summary: "LSASS memory read by an unsigned binary.",
  severity: "critical",
  status: "new",
  riskScore: 91,
  assigneeId: null,
  attack: [{ id: "T1003.001", name: "LSASS Memory", tactic: "credential-access" }],
  alertCount: 2,
  assetIds: ["33333333-3333-4333-8333-333333333333"],
  identityIds: [],
  detectedAt: now,
  acknowledgedAt: null,
  containedAt: null,
  closedAt: null,
  createdAt: now,
  updatedAt: now,
};

function baseApi(extra: Record<string, unknown> = {}) {
  return mockApi({
    "/auth/me": makeMe(),
    "/command-center/summary": makeSummary(),
    "/escalations": EMPTY,
    "/response/actions": EMPTY,
    "/incidents": EMPTY,
    "/reports/schedules": [],
    ...extra,
  });
}

describe("MSSP Command Center", () => {
  it("renders portfolio KPIs and switches organization on click-through", async () => {
    baseApi({ "/mssp/overview": makeMsspOverview() });
    renderApp("/mssp");
    const kpis = await screen.findByTestId("mssp-kpis");
    await waitFor(() => expect(within(kpis).getByRole("link", { name: "Assets: 128.4K" })).toBeInTheDocument());
    expect(within(kpis).getByRole("link", { name: "Critical: 17" })).toBeInTheDocument();
    expect(within(kpis).getByRole("link", { name: "Events / day: 1.3B" })).toBeInTheDocument();
    const row = screen.getByText("Acme Corp").closest("tr")!;
    expect(row).toHaveTextContent("$12,400");
    expect(screen.getByText("Total MRR $16,500")).toBeInTheDocument();
    fireEvent.click(row);
    await waitFor(() => expect(getLocation()).toEqual({ pathname: "/", search: `?org=${ORG_A}` }));
  });

  it("explains itself to non-MSSP accounts instead of failing", async () => {
    const me = makeMe();
    baseApi({ "/auth/me": { ...me, account: { ...me.account, kind: "enterprise" } } });
    renderApp("/mssp");
    expect(await screen.findByText(/available to MSSP accounts/)).toBeInTheDocument();
  });
});

describe("Incidents", () => {
  it("lists incidents, opens the drill-down drawer and updates status", async () => {
    const { calls } = baseApi({
      "/incidents": { items: [INCIDENT], nextCursor: null },
      [`/incidents/${INCIDENT.id}`]: INCIDENT,
      [`PATCH /incidents/${INCIDENT.id}`]: ({ body }: { body: unknown }) => ({ ...INCIDENT, ...(body as object) }),
      "/alerts": EMPTY,
      "/users": [],
    });
    renderApp("/incidents?severity=critical");
    fireEvent.click(await screen.findByText("Credential dumping on DC01"));
    const drawer = await screen.findByRole("dialog");
    expect(await within(drawer).findByText("LSASS memory read by an unsigned binary.")).toBeInTheDocument();
    expect(within(drawer).getByRole("link", { name: /T1003.001/ })).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1003/001/");
    expect(within(drawer).getByRole("link", { name: /Ask AI/ })).toHaveAttribute("href", `/ai?context=${encodeURIComponent(`incident:${INCIDENT.id}`)}`);
    fireEvent.change(within(drawer).getByLabelText("Status"), { target: { value: "investigating" } });
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH" && (c.body as { status?: string }).status === "investigating")).toBe(true));
    const list = calls.find((c) => c.path === "/incidents" && c.method === "GET" && c.url.searchParams.has("severity"))!;
    expect(list.url.searchParams.get("severity")).toBe("critical");
    expect(list.url.searchParams.get("status")).toBe("new,triage,investigating,contained");
  });

  it("parses URL filters defensively", () => {
    expect(parseSeverityParam("critical,bogus,high")).toEqual(["critical", "high"]);
    expect(parseStatusParam(null).mode).toBe("active");
    expect(parseStatusParam("all")).toEqual({ mode: "all", statuses: [] });
    expect(parseStatusParam("closed,nope")).toEqual({ mode: "custom", statuses: ["closed"] });
  });
});

describe("Trial Manager", () => {
  it("shows module states and starts a trial", async () => {
    const { calls } = baseApi({
      "/auth/me": makeMe({
        plan: "trial",
        entitlements: [
          { module: "edr", state: "active", trialEndsAt: null },
          { module: "itdr", state: "trial_ended", trialEndsAt: "2026-09-01T00:00:00.000Z" },
          { module: "siem", state: "available", trialEndsAt: null },
        ],
      }),
      "/entitlements": EMPTY,
      "POST /entitlements/siem/trial": { module: "siem", state: "trial", trialEndsAt: "2099-01-01T00:00:00.000Z" },
    });
    renderApp("/trials");
    expect(await screen.findByRole("heading", { name: "Trial Manager" })).toBeInTheDocument();
    const edr = screen.getByRole("article", { name: "Endpoint Detection & Response" });
    expect(within(edr).getByText("Subscription Active")).toBeInTheDocument();
    const itdr = screen.getByRole("article", { name: "Identity Threat Detection & Response" });
    expect(within(itdr).getByText("Trial Ended")).toBeInTheDocument();
    const siem = screen.getByRole("article", { name: "Security Information & Event Management" });
    fireEvent.click(within(siem).getByRole("button", { name: /Start trial/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/entitlements/siem/trial")).toBe(true));
  });
});

describe("Reports & automations", () => {
  it("renders the report catalog by audience and existing schedules", async () => {
    baseApi({
      "/reports/types": [
        { key: "executive", label: "Executive / CISO summary", audience: "business" },
        { key: "soc_operations", label: "SOC operations", audience: "soc" },
        { key: "mssp_portfolio", label: "MSSP portfolio & revenue", audience: "mssp" },
      ],
      "/reports/schedules": [
        { id: "s1", tenantId: TENANT_ID, organizationId: null, type: "executive", name: "Weekly board pack", cron: "0 7 * * 1", format: "pdf", periodDays: 7, channelIds: ["c1"], enabled: true, lastRunAt: null },
      ],
      "/notifications/channels": [{ id: "c1", tenantId: TENANT_ID, organizationId: null, name: "Board", kind: "email", config: { to: ["board@x.test"] }, enabled: true }],
    });
    renderApp("/reports");
    const catalog = await screen.findByTestId("report-catalog");
    expect(within(catalog).getByText("MSSP portfolio & revenue")).toBeInTheDocument();
    expect(await screen.findByText("Weekly board pack")).toBeInTheDocument();
    expect(screen.getByText("Weekly on Monday at 07:00 UTC")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: /SOC/ }));
    expect(within(screen.getByTestId("report-catalog")).queryByText("Executive / CISO summary")).not.toBeInTheDocument();
  });

  it("creates an email channel with validated recipients", async () => {
    const { calls } = baseApi({ "/notifications/channels": [], "POST /notifications/channels": { id: "new" } });
    renderApp("/soar/channels?create=1");
    const dialog = await screen.findByRole("dialog", { name: "Add notification channel" });
    fireEvent.change(within(dialog).getByLabelText(/^Name/), { target: { value: "SOC on-call" } });
    fireEvent.change(within(dialog).getByLabelText(/^Recipients/), { target: { value: "soc@x.test, bad-address" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Add channel" }));
    expect(await within(dialog).findByText("Invalid address: bad-address")).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText(/^Recipients/), { target: { value: "soc@x.test\nCISO@x.test" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Add channel" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/notifications/channels")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toEqual({ name: "SOC on-call", kind: "email", organizationId: null, config: { to: ["soc@x.test", "ciso@x.test"] }, enabled: true });
  });

  it("creates an automation rule from a recommended template", async () => {
    const { calls } = baseApi({
      "/automations": [],
      "/notifications/channels": [{ id: "c1", tenantId: TENANT_ID, organizationId: null, name: "SOC on-call", kind: "email", config: { to: ["soc@x.test"] }, enabled: true }],
      "POST /automations": { id: "r1" },
    });
    renderApp("/soar/automations");
    fireEvent.click(await screen.findByRole("button", { name: /Email on-call for critical incidents/ }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(await within(dialog).findByRole("checkbox", { name: /SOC on-call/ }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Create rule" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/automations")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toMatchObject({
      name: "Email on-call for critical incidents",
      event: "incident.created",
      conditions: [{ field: "severity", op: "eq", value: "critical" }],
      channelIds: ["c1"],
      throttleMinutes: 0,
      enabled: true,
    });
  });

  it("validation helpers", () => {
    expect(parseRecipients("a@x.io; b@y.io a@x.io nope")).toEqual({ valid: ["a@x.io", "b@y.io"], invalid: ["nope"] });
    expect(isSafeWebhookUrl("https://hooks.slack.com/services/x")).toBe(true);
    expect(isSafeWebhookUrl("http://hooks.example")).toBe(false);
    expect(isSafeWebhookUrl("https://user:pw@hooks.example")).toBe(false);
    expect(coerceConditionValue("in", "critical, high")).toEqual(["critical", "high"]);
    expect(coerceConditionValue("gte", "7.5")).toBe(7.5);
    expect(coerceConditionValue("eq", "true")).toBe(true);
    expect(coerceConditionValue("exists", "x")).toBeUndefined();
  });
});
