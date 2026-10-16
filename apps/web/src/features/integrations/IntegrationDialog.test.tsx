import { ENGINES } from "@bloody/contracts";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { mockApi, renderWithSession } from "../../test/utils";
import { IntegrationDialog } from "./IntegrationDialog";

const wazuh = ENGINES.find((e) => e.key === "wazuh")!;
const velociraptor = ENGINES.find((e) => e.key === "velociraptor")!;

describe("Wazuh integration — isolation allow-list", () => {
  it("validates and sends the API user and isolation allow-list", async () => {
    const { calls } = mockApi({ "POST /integrations": ({ body }: { body: unknown }) => ({ ...(body as object), id: "00000000-0000-4000-8000-000000000099", hasCredential: true, status: "pending" }) });
    const onClose = vi.fn();
    renderWithSession(<IntegrationDialog engine={wazuh} onClose={onClose} />);
    const section = await screen.findByTestId("wazuh-response");
    fireEvent.change(screen.getByLabelText(/Endpoint/), { target: { value: "https://wazuh.mssp.example:55000" } });
    fireEvent.change(screen.getByLabelText(/^Credential/), { target: { value: "wazuh-api-password" } });
    fireEvent.change(within(section).getByLabelText(/Isolation allow-list/), { target: { value: "wazuh.local" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    expect(await within(section).findByText("Enter the Wazuh API user SCIAT signs in as")).toBeInTheDocument();
    expect(within(section).getByText("Not an IP address or CIDR: wazuh.local")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST")).toBe(false);

    fireEvent.change(within(section).getByLabelText(/API user/), { target: { value: "bloody" } });
    fireEvent.change(within(section).getByLabelText(/Isolation allow-list/), { target: { value: "10.0.0.5\n203.0.113.10" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(calls.find((c) => c.method === "POST")!.body).toMatchObject({
      engine: "wazuh",
      config: { username: "bloody", activeResponse: { isolationAllow: ["10.0.0.5", "203.0.113.10"] } },
    });
  });

  it("Velociraptor: sends the SCIAT isolation artifact and allow-list", async () => {
    const { calls } = mockApi({ "POST /integrations": ({ body }: { body: unknown }) => ({ ...(body as object), id: "00000000-0000-4000-8000-000000000098", hasCredential: true, status: "pending" }) });
    const onClose = vi.fn();
    renderWithSession(<IntegrationDialog engine={velociraptor} onClose={onClose} />);
    const section = await screen.findByTestId("velociraptor-isolation");
    fireEvent.change(screen.getByLabelText(/Endpoint/), { target: { value: "https://velo.mssp.example:8001" } });
    fireEvent.change(screen.getByLabelText(/^Credential/), { target: { value: "velo-token" } });
    fireEvent.change(within(section).getByLabelText(/SCIAT isolation artifact/), { target: { value: "Custom.Bloody.Isolate" } });
    fireEvent.change(within(section).getByLabelText(/Isolation allow-list/), { target: { value: "192.168.1.3" } });
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(calls.find((c) => c.method === "POST")!.body).toMatchObject({
      engine: "velociraptor",
      config: { response: { bloodyIsolateArtifact: "Custom.Bloody.Isolate", isolationAllow: ["192.168.1.3"] } },
    });
  });
});
