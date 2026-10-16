import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ORG_A } from "../../test/fixtures";
import { mockApi, renderWithSession } from "../../test/utils";
import { M365HardeningView } from "./M365HardeningView";

const NOW = new Date().toISOString();
const permissions = [{ name: "Policy.Read.All", why: "Conditional Access" }];
const check = (over: Record<string, unknown>) => ({
  id: "m365.x",
  area: "identity",
  title: "A check",
  severity: "high",
  references: ["CISA SCuBA MS.AAD.1.1v1"],
  why: "Because attackers love it.",
  howToFix: ["Open the Entra admin center", "Turn it on"],
  status: "pass",
  summary: "ok",
  evidence: [],
  ...over,
});
const connected = {
  organizationId: ORG_A,
  connection: { id: "c1", organizationId: ORG_A, directoryTenantId: "nile.onmicrosoft.com", clientId: "x", displayName: "Nile Health", status: "connected", lastError: null, lastAssessedAt: NOW, lastScore: 42, createdAt: NOW },
  assessment: {
    id: "a1",
    connectionId: "c1",
    organizationId: ORG_A,
    tenantName: "Nile Health",
    startedAt: NOW,
    finishedAt: NOW,
    score: 42,
    counts: { pass: 1, fail: 1, warn: 0, unknown: 1, manual: 0 },
    results: [
      check({ id: "m365.legacy_auth_blocked", title: "Legacy authentication is blocked", severity: "critical", status: "fail", summary: "No enabled policy blocks legacy authentication.", howToFix: ["Go to Protection → Conditional Access → Policies → New policy."] }),
      check({ id: "m365.user_consent", title: "Users cannot consent to apps", status: "unknown", summary: "Bloody could not read this setting.", evidence: ["grant the Policy.Read.All application permission"] }),
      check({ id: "m365.mfa_all_users", title: "MFA is required for every user", status: "pass" }),
    ],
  },
  history: [{ id: "a1", finishedAt: NOW, score: 42 }],
  permissions,
  checks: 21,
};

describe("Microsoft 365 hardening", () => {
  it("guides setup and connects with the app registration details", async () => {
    const { calls } = mockApi({
      "/m365/overview": { organizationId: ORG_A, connection: null, assessment: null, history: [], permissions, checks: 21 },
      "POST /m365/connections": { connection: connected.connection, assessment: connected.assessment, error: null },
    });
    renderWithSession(<M365HardeningView />);
    expect(await screen.findByText("Policy.Read.All")).toBeInTheDocument();
    const go = screen.getByRole("button", { name: "Connect and assess" });
    expect(go).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Directory (tenant) ID"), { target: { value: "nile.onmicrosoft.com" } });
    fireEvent.change(screen.getByLabelText("Application (client) ID"), { target: { value: "11111111-2222-3333-4444-555555555555" } });
    fireEvent.change(screen.getByLabelText("Client secret value"), { target: { value: "s3cr3t-value" } });
    fireEvent.click(go);
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ organizationId: ORG_A, directoryTenantId: "nile.onmicrosoft.com", clientId: "11111111-2222-3333-4444-555555555555", clientSecret: "s3cr3t-value" }));
  });

  it("shows the score, what to fix first and how, and what could not be read", async () => {
    const { calls } = mockApi({ "/m365/overview": connected, "POST /m365/connections/c1/assess": connected.assessment });
    renderWithSession(<M365HardeningView />);
    expect(await screen.findByText("42%")).toBeInTheDocument();
    // Failing checks open by default with the fix steps.
    expect(screen.getByText("Legacy authentication is blocked")).toBeInTheDocument();
    expect(screen.getByText("Go to Protection → Conditional Access → Policies → New policy.")).toBeInTheDocument();
    expect(screen.queryByText("MFA is required for every user")).toBeNull(); // passing ones are under "Passing"
    fireEvent.click(screen.getByRole("tab", { name: /Not readable/ }));
    fireEvent.click(screen.getByRole("button", { name: /Users cannot consent to apps/ }));
    expect(screen.getByText(/grant the Policy.Read.All application permission/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Run assessment now" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/m365/connections/c1/assess")).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "Disconnect" }));
    expect(within(await screen.findByRole("dialog")).getByText(/deletes the stored app secret/)).toBeInTheDocument();
  });
});
