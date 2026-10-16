import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ORG_A } from "../../test/fixtures";
import { mockApi, renderWithSession } from "../../test/utils";
import { AppControlView } from "./AppControlView";

const NOW = new Date().toISOString();
const overview = (mode: "off" | "audit" | "enforce" = "audit") => ({
  organizationId: ORG_A,
  mode,
  updatedAt: NOW,
  updatedBy: null,
  rules: [{ id: "00000000-0000-4000-8000-000000000a01", organizationId: ORG_A, action: "block", kind: "name", value: "AnyDesk.exe", platform: "any", note: "Unapproved remote access", createdBy: null, createdAt: NOW }],
  stats: { agents: 3, blocked24h: 0, audited24h: 2, programs: 2 },
});

describe("App Control", () => {
  it("asks before enforcing, and shows the policy's rules", async () => {
    const { calls } = mockApi({ "/app-control/overview": overview(), [`PUT /app-control/settings/${ORG_A}`]: { mode: "enforce" } });
    renderWithSession(<AppControlView />);
    expect(await screen.findByText("AnyDesk.exe")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "Audit" })).toHaveAttribute("aria-checked", "true");
    fireEvent.click(screen.getByRole("radio", { name: "Enforce" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/will stop every program that matches a block rule/)).toBeInTheDocument();
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
    fireEvent.click(within(dialog).getByRole("button", { name: "Enforce" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ mode: "enforce" }));
  });

  it("blocks a program straight from the applications list", async () => {
    const { calls } = mockApi({
      "/app-control/overview": overview(),
      "/app-control/inventory": { items: [{ name: "TeamViewer.exe", path: "C:\\Users\\amina\\Downloads\\TeamViewer.exe", sha256: null, publisher: null, endpoints: 2, lastSeenAt: NOW, verdict: "none" }] },
      "POST /app-control/rules": ({ body }: { body: unknown }) => ({ ...(body as object), id: "00000000-0000-4000-8000-000000000a02", note: null, createdBy: null, createdAt: NOW }),
    });
    renderWithSession(<AppControlView />);
    fireEvent.click(await screen.findByRole("tab", { name: /Applications/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Block" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByLabelText("Value")).toHaveValue("TeamViewer.exe");
    fireEvent.click(within(dialog).getByRole("button", { name: "Add block rule" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({ organizationId: ORG_A, action: "block", kind: "name", value: "TeamViewer.exe", platform: "any" }));
  });

  it("shows what was stopped or would be stopped", async () => {
    mockApi({
      "/app-control/overview": overview(),
      "/app-control/events": { items: [{ id: "00000000-0000-4000-8000-000000000e01", organizationId: ORG_A, agentId: "00000000-0000-4000-8000-0000000000e1", hostname: "kb-ws-07", name: "AnyDesk.exe", path: "C:\\Users\\x\\AnyDesk.exe", sha256: null, publisher: null, ruleId: "00000000-0000-4000-8000-000000000a01", verdict: "audited", occurredAt: NOW }] },
    });
    renderWithSession(<AppControlView />);
    fireEvent.click(await screen.findByRole("tab", { name: /Activity/ }));
    expect(await screen.findByText("kb-ws-07")).toBeInTheDocument();
    expect(screen.getByText("would stop")).toBeInTheDocument();
  });
});
