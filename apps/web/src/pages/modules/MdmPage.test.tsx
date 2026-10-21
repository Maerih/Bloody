import { DEFAULT_ANDROID_POLICY, type MobileDevice, type MobileOverview } from "@bloody/contracts";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ORG_A } from "../../test/fixtures";
import { mockApi, renderWithSession } from "../../test/utils";
import { MdmDevicesSection, MdmEnrollSection, MdmSetupSection } from "./MdmPage";

const NOW = new Date().toISOString();
const device = (id: string, over: Partial<MobileDevice> = {}): MobileDevice => ({
  id,
  organizationId: ORG_A,
  assetId: `00000000-0000-4000-8000-0000000000${id}`,
  platform: "android",
  name: `Samsung SM-A546E (${id})`,
  manufacturer: "Samsung",
  model: "SM-A546E",
  serialNumber: `R58N${id}`,
  osVersion: "14",
  securityPatchLevel: "2026-09-05",
  ownership: "company",
  managementMode: "DEVICE_OWNER",
  assignee: "Amina Mushi",
  userName: null,
  state: "ACTIVE",
  compliance: "compliant",
  findings: [],
  enrolledAt: NOW,
  lastStatusAt: NOW,
  lastSyncAt: NOW,
  ...over,
});

const overview = (over: Partial<MobileOverview> = {}): MobileOverview => ({
  organizationId: ORG_A,
  account: { configured: true, projectId: "sciat-mdm-01", clientEmail: "mdm@sciat-mdm-01.iam.gserviceaccount.com", status: "ok", lastError: null, updatedAt: NOW },
  enterprise: { id: "e1", organizationId: ORG_A, status: "active", enterpriseName: "enterprises/LC04xkq1", displayName: "Acme Corp", policy: DEFAULT_ANDROID_POLICY, policySyncedAt: NOW, lastSyncAt: NOW, lastError: null, createdAt: NOW },
  tokens: [],
  devices: [
    device("a1", { compliance: "at_risk", assignee: "Joseph Mrema", findings: [{ key: "compromised", severity: "critical", title: "Device may be compromised (rooted or modified Android)", detail: "COMPROMISED_OS" }] }),
    device("a2"),
  ],
  counts: { total: 2, compliant: 1, non_compliant: 0, at_risk: 1, stale: 0, pending: 0 },
  ...over,
});

afterEach(() => vi.restoreAllMocks());

describe("Mobile Device Management", () => {
  it("lists phones with compliance, explains findings and offers lock / wipe through response actions", async () => {
    const { calls } = mockApi({ "/mobile/overview": overview(), "POST /mobile/android/sync": { devices: 2, removed: 0 }, "/response/catalog": { items: [], policy: null } });
    renderWithSession(<MdmDevicesSection />);
    const table = await screen.findByRole("table", { name: "Mobile devices" });
    expect(within(table).getByText("At risk")).toBeInTheDocument();
    fireEvent.click(within(table).getByText("Samsung SM-A546E (a1)"));
    const drawer = await screen.findByRole("dialog", { name: "Samsung SM-A546E (a1)" });
    expect(within(drawer).getByText("Device may be compromised (rooted or modified Android)")).toBeInTheDocument();
    fireEvent.click(within(drawer).getByRole("button", { name: "Lock / wipe" }));
    const dialog = await screen.findByRole("dialog", { name: /request response action/i });
    const options = within(dialog).getAllByRole("option").map((o) => o.textContent);
    expect(options).toEqual(expect.arrayContaining(["Lock mobile device", "Wipe mobile device (factory reset)"]));
    expect(within(dialog).getByText(/Wipe factory-resets this company phone/)).toBeInTheDocument();

    fireEvent.click(screen.getAllByRole("button", { name: /cancel|close/i })[0]!);
    fireEvent.click(screen.getByRole("button", { name: "Sync now" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST" && c.path === "/mobile/android/sync")?.body).toEqual({ organizationId: ORG_A }));
  });

  it("points to setup until the Google account and enterprise exist", async () => {
    mockApi({ "/mobile/overview": overview({ account: { configured: false, projectId: null, clientEmail: null, status: null, lastError: null, updatedAt: null }, enterprise: null, devices: [], counts: { total: 0, compliant: 0, non_compliant: 0, at_risk: 0, stale: 0, pending: 0 } }) });
    renderWithSession(<MdmDevicesSection />);
    expect(await screen.findByText("Connect your Google account first")).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("creates an enrollment QR code; personal phones get the work-profile link", async () => {
    const token = { id: "t1", ownership: "personal", assignee: "Amina Mushi", value: "ABCDEFGHIJ", qrCode: "{}", expiresAt: "2026-12-01T00:00:00.000Z", createdBy: null, createdAt: NOW };
    const { calls } = mockApi({ "/mobile/overview": overview({ tokens: [token as never] }), "POST /mobile/android/enrollment-tokens": token });
    renderWithSession(<MdmEnrollSection />);
    expect(await screen.findByRole("img", { name: "Enrollment QR code for Amina Mushi" })).toBeInTheDocument();
    expect(screen.getAllByText("https://enterprise.google.com/android/enroll?et=ABCDEFGHIJ").length).toBeGreaterThan(0);
    fireEvent.change(screen.getByLabelText("Whose phone"), { target: { value: "personal" } });
    fireEvent.change(screen.getByLabelText(/^For/), { target: { value: "Joseph Mrema" } });
    fireEvent.change(screen.getByLabelText("Valid for"), { target: { value: "30" } });
    fireEvent.click(screen.getByRole("button", { name: "Create QR code" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ organizationId: ORG_A, ownership: "personal", validDays: 30, assignee: "Joseph Mrema" }));
  });

  it("connects the Google key and starts the customer's Android Enterprise sign-up", async () => {
    const assign = vi.fn();
    vi.spyOn(window, "location", "get").mockReturnValue({ ...window.location, assign } as Location);
    const { calls } = mockApi({
      "/mobile/overview": overview({ account: { configured: false, projectId: null, clientEmail: null, status: null, lastError: null, updatedAt: null }, enterprise: null }),
      "PUT /mobile/android/account": overview().account,
      "POST /mobile/android/enterprise/signup": { url: "https://enterprise.google.com/signup/android/email?token=abc" },
    });
    renderWithSession(<MdmSetupSection />);
    const key = JSON.stringify({ type: "service_account", project_id: "sciat-mdm-01", private_key: "-----BEGIN PRIVATE KEY-----" });
    fireEvent.change(await screen.findByLabelText("…or paste its contents"), { target: { value: key } });
    fireEvent.click(screen.getByRole("button", { name: "Check and connect" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ serviceAccountJson: key }));
    expect(screen.getByText("Connect the Google account first.")).toBeInTheDocument();
  });

  it("starts Google's sign-up for the organization", async () => {
    const assign = vi.fn();
    vi.spyOn(window, "location", "get").mockReturnValue({ ...window.location, assign } as Location);
    const { calls } = mockApi({ "/mobile/overview": overview({ enterprise: null }), "POST /mobile/android/enterprise/signup": { url: "https://enterprise.google.com/signup/android/email?token=abc" } });
    renderWithSession(<MdmSetupSection />);
    fireEvent.change(await screen.findByLabelText(/Customer admin email/), { target: { value: "it@acme.example" } });
    fireEvent.click(screen.getByRole("button", { name: "Create Android Enterprise with Google" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("https://enterprise.google.com/signup/android/email?token=abc"));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ organizationId: ORG_A, adminEmail: "it@acme.example" });
  });
});
