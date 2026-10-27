import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { makeMe, USER_ID } from "../../test/fixtures";
import { mockApi, renderApp, renderWithSession } from "../../test/utils";
import { MfaCard } from "./MfaCard";
import { MfaPolicyCard } from "./MfaPolicyCard";

const SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const user = (mfaEnabled: boolean, mfaSetupRequired = false) => ({ id: USER_ID, email: "analyst@example.test", displayName: "Test Analyst", mfaEnabled, mfaSetupRequired });
const session = { id: "s1", method: "password" as const, mfaVerified: true };

function typeCode(code: string) {
  fireEvent.change(screen.getByRole("textbox", { name: /code/i }), { target: { value: code } });
}

describe("MFA in Preferences", () => {
  it("sets up an authenticator: QR code and key, then confirms with a code", async () => {
    const { calls } = mockApi({
      "POST /auth/mfa/totp/enroll": { secret: SECRET, otpauthUri: `otpauth://totp/SCIAT%3Aanalyst?secret=${SECRET}&issuer=SCIAT` },
      "POST /auth/mfa/totp/confirm": { mfaEnabled: true },
      "/auth/me": makeMe({ user: user(true), session }),
    });
    renderWithSession(<MfaCard />, { me: makeMe({ user: user(false), session }) });
    expect(screen.getByText("Off")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Set up authenticator app" }));
    expect(await screen.findByRole("img", { name: "QR code for your authenticator app" })).toBeInTheDocument();
    expect(screen.getByTestId("mfa-secret")).toHaveTextContent("JBSW Y3DP EHPK 3PXP");

    const submit = screen.getByRole("button", { name: "Turn on MFA" });
    expect(submit).toBeDisabled();
    typeCode("12a3456");
    expect(screen.getByRole("textbox", { name: /code/i })).toHaveValue("123456");
    fireEvent.click(submit);
    await waitFor(() => expect(calls.find((c) => c.path === "/auth/mfa/totp/confirm")?.body).toEqual({ code: "123456" }));
  });

  it("shows a wrong code and lets the person try again", async () => {
    mockApi({
      "POST /auth/mfa/totp/enroll": { secret: SECRET, otpauthUri: `otpauth://totp/x?secret=${SECRET}` },
      "POST /auth/mfa/totp/confirm": { status: 400, body: { error: { code: "invalid_mfa_code", message: "Invalid verification code" } } },
    });
    renderWithSession(<MfaCard />, { me: makeMe({ user: user(false), session }) });
    fireEvent.click(screen.getByRole("button", { name: "Set up authenticator app" }));
    await screen.findByRole("img", { name: /QR code/ });
    typeCode("000000");
    fireEvent.click(screen.getByRole("button", { name: "Turn on MFA" }));
    expect(await screen.findByText("Invalid verification code")).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: /code/i })).toHaveValue("");
  });

  it("turns MFA off with a code when the account does not require it", async () => {
    const { calls } = mockApi({ "POST /auth/mfa/totp/disable": { mfaEnabled: false }, "/auth/me": makeMe({ user: user(false), session }) });
    renderWithSession(<MfaCard />, { me: makeMe({ user: user(true), session }) });
    expect(screen.getByText("On")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Turn off" }));
    typeCode("654321");
    fireEvent.click(screen.getByRole("button", { name: "Turn off MFA" }));
    await waitFor(() => expect(calls.find((c) => c.path === "/auth/mfa/totp/disable")?.body).toEqual({ code: "654321" }));
  });

  it("keeps MFA on when the account requires it", () => {
    mockApi({});
    const me = makeMe({ user: user(true), session });
    renderWithSession(<MfaCard />, { me: { ...me, account: { ...me.account, requireMfa: true } } });
    expect(screen.queryByRole("button", { name: "Turn off" })).not.toBeInTheDocument();
    expect(screen.getByText(/Your account requires MFA, so it stays on/)).toBeInTheDocument();
  });
});

describe("Required MFA", () => {
  it("shows the setup screen instead of the console until MFA is set up", async () => {
    const me = makeMe({ user: user(false, true), session });
    mockApi({ "/auth/me": { ...me, account: { ...me.account, requireMfa: true } } });
    renderApp("/");
    expect(await screen.findByRole("heading", { name: /Set up multi-factor authentication/ })).toBeInTheDocument();
    expect(screen.getByText(/Fixture Security requires an authenticator app for every sign-in/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Set up authenticator app" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Primary" })).not.toBeInTheDocument();
  });
});

describe("MFA policy (Users & Teams)", () => {
  it("lets an administrator who uses MFA require it for everyone", async () => {
    const { calls } = mockApi({ "/auth/mfa/policy": { requireMfa: false, usersWithMfa: 3, usersWithoutMfa: 5 }, "PUT /auth/mfa/policy": { requireMfa: true } });
    renderWithSession(<MfaPolicyCard />, { me: makeMe({ user: user(true), session }) });
    expect(await screen.findByText("MFA is optional")).toBeInTheDocument();
    expect(screen.getByText(/3 people use an authenticator app, 5 do not/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Require MFA for everyone" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ requireMfa: true }));
  });

  it("asks an administrator without MFA to set it up first", async () => {
    mockApi({ "/auth/mfa/policy": { requireMfa: false, usersWithMfa: 0, usersWithoutMfa: 4 } });
    renderWithSession(<MfaPolicyCard />, { me: makeMe({ user: user(false), session }) });
    expect(await screen.findByRole("button", { name: "Require MFA for everyone" })).toBeDisabled();
    expect(screen.getByText("Set up MFA for yourself first in Preferences.")).toBeInTheDocument();
  });
});
