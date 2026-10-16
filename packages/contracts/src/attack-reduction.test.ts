import { describe, expect, it } from "vitest";
import { ASR_RECOMMENDED, ASR_STANDARD, HARDENING_CHECKS, evaluateHardening, hardeningScore, parseAsr } from "./attack-reduction.js";
import { HostInventoryReport } from "./host-inventory.js";

const users = [
  { name: "Administrator", admin: true, enabled: false },
  { name: "it-admin", admin: true, enabled: true },
  { name: "Guest", admin: false, enabled: false },
];
const block = (ids: string[]) => ids.map((id) => `${id}=1`).join(",");

describe("attack reduction", () => {
  it("has unique keys, a platform and a fix for every check", () => {
    expect(new Set(HARDENING_CHECKS.map((c) => c.key)).size).toBe(HARDENING_CHECKS.length);
    for (const c of HARDENING_CHECKS) expect(c.platforms.length && c.fix && c.why && c.attack, c.key).toBeTruthy();
  });

  it("grades a hardened and a weak Windows computer", () => {
    const hardened = evaluateHardening("windows", {
      users,
      firewall: { enabled: true },
      facts: {
        smb1_enabled: false, llmnr_disabled: true, netbios_enabled_adapters: 0, wdigest_use_logon_credential: null, lsa_run_as_ppl: 1, credential_guard_running: true,
        rdp_enabled: true, rdp_nla: true, powershell_v2_enabled: false, ps_scriptblock_logging: true, uac_enabled: true, uac_admin_prompt: 5, autorun_disabled: true,
        bitlocker_os_protected: true, asr_rules: block([...Object.keys(ASR_STANDARD), ...Object.keys(ASR_RECOMMENDED)]), last_patch_days: 12, smb_signing_required: true, lm_compat_level: 5,
      },
    });
    expect(hardened.filter((r) => r.status !== "pass")).toEqual([]);
    expect(hardeningScore(hardened)).toBe(100);

    const weak = evaluateHardening("windows", {
      users: [...users, { name: "amina", admin: true, enabled: true }, { name: "joe", admin: true, enabled: true }, { name: "guest", admin: false, enabled: true }],
      firewall: { enabled: false },
      facts: { smb1_enabled: true, llmnr_disabled: false, wdigest_use_logon_credential: 1, rdp_enabled: "1", rdp_nla: "0", uac_enabled: true, uac_admin_prompt: 0, asr_rules: `${Object.keys(ASR_STANDARD)[0]}=2`, last_patch_days: 80, lm_compat_level: 3 },
    });
    const by = Object.fromEntries(weak.map((r) => [r.key, r]));
    expect(by.win_smb1!.status).toBe("fail");
    expect(by.win_wdigest!.status).toBe("fail");
    expect(by.win_rdp_nla).toMatchObject({ status: "fail", detail: "Remote Desktop is on without NLA" });
    expect(by.win_uac).toMatchObject({ status: "fail", detail: "Administrators are elevated without a prompt" });
    expect(by.win_asr_standard!.detail).toContain("Block credential stealing from LSASS");
    expect(by.win_asr_recommended).toMatchObject({ status: "fail", detail: "0 of 11 blocking" });
    expect(by.local_admins).toMatchObject({ status: "fail", detail: "3 enabled administrators: it-admin, amina, joe" });
    expect(by.win_guest!.status).toBe("fail");
    expect(by.win_bitlocker!.status).toBe("unknown");
    const score = hardeningScore(weak)!;
    expect(score).toBeLessThan(20);
    // Weighted by severity (high 3, medium 2); accepting a gap takes it out of the score.
    const two = [{ key: "win_smb1", status: "fail" as const, detail: null }, { key: "win_ps_logging", status: "pass" as const, detail: null }];
    expect(hardeningScore(two)).toBe(40);
    expect(hardeningScore(two, new Set(["win_smb1"]))).toBe(100);
    expect(hardeningScore([{ key: "win_smb1", status: "unknown", detail: null }])).toBeNull();
  });

  it("only applies a platform's checks, and handles Linux without SSH", () => {
    const linux = evaluateHardening("linux", { users: [], firewall: null, facts: { ssh_permit_root_login: "none", ssh_password_auth: "none", aslr: 2, uid0_accounts: "root,toor" } });
    expect(linux.every((r) => !r.key.startsWith("win_") && !r.key.startsWith("mac_"))).toBe(true);
    const by = Object.fromEntries(linux.map((r) => [r.key, r.status]));
    expect(by).toMatchObject({ linux_ssh_root: "na", linux_ssh_password: "na", linux_aslr: "pass", linux_uid0: "fail", firewall: "unknown" });
    expect(parseAsr("9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2=1, junk")).toEqual(new Map([["9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", 1]]));
  });

  it("accepts hardening facts in the inventory report, and refuses malformed ones", () => {
    expect(HostInventoryReport.parse({ hardening: { smb1_enabled: false, asr_rules: "" } }).hardening).toEqual({ smb1_enabled: false, asr_rules: "" });
    expect(HostInventoryReport.parse({}).hardening).toEqual({});
    expect(HostInventoryReport.safeParse({ hardening: { "Bad Key": 1 } }).success).toBe(false);
    expect(HostInventoryReport.safeParse({ hardening: { x: { nested: true } } }).success).toBe(false);
  });
});

describe("agent fixes", () => {
  it("only offers fixes for known checks on the right platform", async () => {
    const { AGENT_FIXABLE, agentCanFix, hardeningCheck } = await import("./attack-reduction.js");
    for (const k of AGENT_FIXABLE) expect(hardeningCheck(k), k).toBeTruthy();
    expect(agentCanFix("win_smb1", "windows")).toBe(true);
    expect(agentCanFix("win_smb1", "linux")).toBe(false);
    expect(agentCanFix("win_bitlocker", "windows")).toBe(false);
    expect(agentCanFix("linux_ssh_root", "linux")).toBe(false);
  });
});
