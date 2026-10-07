import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { makeMe, makeOrg, ORG_A, ORG_B } from "../test/fixtures";
import { getLocation, renderWithSession } from "../test/utils";
import { useSession } from "./session";

function Probe() {
  const s = useSession();
  return (
    <div>
      <span data-testid="org">{s.organizationId ?? "all"}</span>
      <span data-testid="role">{s.dashboardRole}</span>
      <span data-testid="can-write">{String(s.can("incident:write"))}</span>
      <span data-testid="edr">{s.moduleState("edr")}</span>
      <span data-testid="cspm">{s.moduleState("cspm")}</span>
      <button type="button" onClick={() => s.setOrganizationId(ORG_B)}>
        pick-b
      </button>
      <button type="button" onClick={() => s.setOrganizationId("not-an-org")}>
        pick-bad
      </button>
    </div>
  );
}

describe("SessionProvider", () => {
  it("defaults MSSP admins to All organizations and syncs ?org=all", async () => {
    renderWithSession(<Probe />);
    expect(screen.getByTestId("org")).toHaveTextContent("all");
    expect(screen.getByTestId("role")).toHaveTextContent("mssp_admin");
    await waitFor(() => expect(getLocation().search).toBe("?org=all"));
  });

  it("honours a valid deep link and ignores an invalid one", async () => {
    renderWithSession(<Probe />, { route: `/?org=${ORG_A}` });
    expect(screen.getByTestId("org")).toHaveTextContent(ORG_A);
    fireEvent.click(screen.getByText("pick-bad"));
    expect(screen.getByTestId("org")).toHaveTextContent(ORG_A);
    fireEvent.click(screen.getByText("pick-b"));
    await waitFor(() => expect(screen.getByTestId("org")).toHaveTextContent(ORG_B));
    expect(getLocation().search).toBe(`?org=${ORG_B}`);
  });

  it("replaces an org the principal cannot see with the stored selection", async () => {
    renderWithSession(<Probe />, { route: "/?org=99999999-9999-4999-8999-999999999999" });
    expect(screen.getByTestId("org")).toHaveTextContent("all");
    await waitFor(() => expect(getLocation().search).toBe("?org=all"));
  });

  it("pins single-organization customers to their organization without URL noise", () => {
    const org = makeOrg(ORG_A, "Acme Corp", "acme");
    renderWithSession(<Probe />, { me: makeMe({ bindings: [{ role: "customer_viewer", organizationId: ORG_A }], organizations: [org], plan: "essentials", entitlements: [] }) });
    expect(screen.getByTestId("org")).toHaveTextContent(ORG_A);
    expect(screen.getByTestId("role")).toHaveTextContent("executive");
    expect(screen.getByTestId("can-write")).toHaveTextContent("false");
    // Plan-derived entitlements when /auth/me lists none: essentials includes EDR, not CSPM.
    expect(screen.getByTestId("edr")).toHaveTextContent("active");
    expect(screen.getByTestId("cspm")).toHaveTextContent("locked");
    expect(getLocation().search).toBe("");
  });
});
