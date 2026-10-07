import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { makeMe, ORG_A, ORG_B } from "../test/fixtures";
import { getLocation, mockApi, renderWithSession } from "../test/utils";
import { TopBar } from "./TopBar";

const EMPTY = { items: [], nextCursor: null };

describe("TopBar", () => {
  beforeEach(() => {
    mockApi({ "/escalations": EMPTY, "/response/actions": EMPTY, "/incidents": EMPTY });
  });

  it("shows the account selector and the primary navigation", () => {
    renderWithSession(<TopBar />);
    expect(screen.getByRole("button", { name: /Account Fixture Security/ })).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Primary" });
    for (const label of ["Organizations", "Assets", "Incidents", "Investigations", "Escalations", "Reports", "Users", "Integrations", "AI SOC"]) {
      expect(within(nav).getByRole("link", { name: label })).toBeInTheDocument();
    }
    expect(screen.getByRole("button", { name: "Contact Sales" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Help" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Settings" })).toBeInTheDocument();
  });

  it("opens the hamburger menu with support, account and profile sections", () => {
    renderWithSession(<TopBar />);
    fireEvent.click(screen.getByRole("button", { name: "Main menu" }));
    const menu = screen.getByRole("navigation", { name: "Main menu" });
    for (const label of ["Support & FAQ", "Download Agent", "Demo Sandbox", "Simulate an Incident"]) {
      expect(within(menu).getByRole("menuitem", { name: new RegExp(label) })).toBeInTheDocument();
    }
    expect(within(menu).getByText("Account")).toBeInTheDocument();
    for (const label of ["Dashboard", "Organizations", "Agents", "Escalations", "Incidents", "Investigations", "Reports", "Hub", "Users", "Integrations", "API Credentials", "Settings", "Billing & Invoices", "Data Archive", "Audit Log"]) {
      expect(within(menu).getByRole("menuitem", { name: new RegExp(`^${label.replace(/[&]/g, "\\&")}`) })).toBeInTheDocument();
    }
    expect(within(menu).getByText("Profile")).toBeInTheDocument();
    for (const label of ["Preferences", "Trial Manager", "Feedback", "Logout"]) {
      expect(within(menu).getByRole("menuitem", { name: new RegExp(label) })).toBeInTheDocument();
    }
    // Escape closes the menu.
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("navigation", { name: "Main menu" })).not.toBeInTheDocument();
  });

  it("hides menu entries the principal has no permission for", () => {
    renderWithSession(<TopBar />, { me: makeMe({ bindings: [{ role: "customer_viewer", organizationId: ORG_A }], organizations: [makeMe().organizations[0]!], plan: "essentials" }) });
    fireEvent.click(screen.getByRole("button", { name: "Main menu" }));
    const menu = screen.getByRole("navigation", { name: "Main menu" });
    expect(within(menu).queryByRole("menuitem", { name: /Audit Log/ })).not.toBeInTheDocument();
    expect(within(menu).queryByRole("menuitem", { name: /API Credentials/ })).not.toBeInTheDocument();
    expect(within(menu).queryByRole("menuitem", { name: /Billing/ })).not.toBeInTheDocument();
    expect(within(menu).getByRole("menuitem", { name: /Escalations/ })).toBeInTheDocument();
    // AI SOC is not in the essentials plan and customer viewers cannot use AI.
    expect(within(screen.getByRole("navigation", { name: "Primary" })).queryByRole("link", { name: "AI SOC" })).not.toBeInTheDocument();
  });

  it("switches organization from the account selector and reflects it in the URL", async () => {
    renderWithSession(<TopBar />);
    await waitFor(() => expect(getLocation().search).toContain("org=all"));
    fireEvent.click(screen.getByRole("button", { name: /Account Fixture Security/ }));
    const list = screen.getByRole("listbox", { name: "Organizations" });
    expect(within(list).getByRole("option", { name: /All organizations/ })).toHaveAttribute("aria-selected", "true");
    fireEvent.click(within(list).getByRole("option", { name: /Globex/ }));
    await waitFor(() => expect(getLocation().search).toContain(`org=${ORG_B}`));
    expect(screen.getByRole("button", { name: /viewing Globex/ })).toBeInTheDocument();
    expect(localStorage.getItem(`bloody.org.${makeMe().principal.tenantId}.${makeMe().principal.id}`)).toBe(JSON.stringify(ORG_B));
  });

  it("shows a red dot and actionable items when escalations are open", async () => {
    mockApi({
      "/escalations": {
        items: [
          {
            id: "11111111-1111-4111-8111-111111111111",
            tenantId: makeMe().principal.tenantId,
            organizationId: ORG_A,
            incidentId: null,
            title: "Confirm isolation of FIN-WS-22",
            severity: "high",
            status: "open",
            dueAt: "2020-01-01T00:00:00.000Z",
            resolvedAt: null,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          },
        ],
        nextCursor: null,
      },
      "/response/actions": EMPTY,
      "/incidents": EMPTY,
    });
    renderWithSession(<TopBar />);
    expect(await screen.findByTestId("notification-dot")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Notifications \(1 new\)/ }));
    expect(screen.getByText("Confirm isolation of FIN-WS-22")).toBeInTheDocument();
    expect(screen.getByText(/overdue/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Mark all as read" }));
    expect(screen.queryByTestId("notification-dot")).not.toBeInTheDocument();
  });
});
