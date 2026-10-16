import type { M365CheckDefinition, M365CheckResult, M365CheckStatus, M365Severity } from "@bloody/contracts";
import { GLOBAL_ADMIN_ROLE, PRIVILEGED_ROLES, type CaPolicy, type M365Snapshot, type Section } from "./collect.js";

/**
 * Microsoft 365 hardening checks (proprietary). Each check is mapped to CISA SCuBA and the CIS
 * Microsoft 365 Foundations Benchmark where they apply, explains why it matters and how to fix it
 * in the admin portals, and grades a collected snapshot. Unreadable settings are "unknown" with
 * the missing permission or licence; settings Microsoft exposes only through Exchange PowerShell
 * are "manual" with guided steps.
 */

type Outcome = { status: M365CheckStatus; summary: string; evidence?: string[] };
interface Check extends M365CheckDefinition {
  evaluate(s: M365Snapshot): Outcome;
}

const PHISHING_RESISTANT_STRENGTH = "00000000-0000-0000-0000-000000000004";
/** Guest role IDs: restricted / limited access are fine; "same as members" is not. */
const GUEST_RESTRICTED = new Set(["2af84b1e-32c8-42b7-82bc-daa82404023b", "10dae51f-b6af-4016-8d66-8c2a99b929b3"]);
/** Delegated scopes that let an app read or send mail or reach files / the directory. */
const HIGH_IMPACT_SCOPES = new Set([
  "mail.read", "mail.readwrite", "mail.send", "mail.readbasic", "mailboxsettings.readwrite", "full_access_as_user", "ews.accessasuser.all", "imap.accessasuser.all", "pop.accessasuser.all", "smtp.send",
  "files.read.all", "files.readwrite.all", "sites.read.all", "sites.readwrite.all", "directory.readwrite.all", "user.readwrite.all", "contacts.readwrite", "calendars.readwrite",
]);

const unavailable = (sec: Section<unknown>): Outcome | null => (sec.ok ? null : { status: "unknown", summary: "Bloody could not read this setting.", evidence: [sec.error] });
const list = (items: string[], max = 25) => (items.length > max ? [...items.slice(0, max), `…and ${items.length - max} more`] : items);

const enabled = (p: CaPolicy) => p.state === "enabled";
const reportOnly = (p: CaPolicy) => p.state === "enabledForReportingButNotEnforced";
const allUsers = (p: CaPolicy) => (p.conditions?.users?.includeUsers ?? []).includes("All");
const allApps = (p: CaPolicy) => (p.conditions?.applications?.includeApplications ?? []).includes("All");
const controls = (p: CaPolicy) => p.grantControls?.builtInControls ?? [];
const blocks = (p: CaPolicy) => controls(p).includes("block");
const requiresMfa = (p: CaPolicy) => controls(p).includes("mfa") || Boolean(p.grantControls?.authenticationStrength?.id);
const coversAdmins = (p: CaPolicy) => allUsers(p) || (p.conditions?.users?.includeRoles ?? []).includes(GLOBAL_ADMIN_ROLE);
const exclusions = (p: CaPolicy) => (p.conditions?.users?.excludeUsers?.length ?? 0) + (p.conditions?.users?.excludeRoles?.length ?? 0) + ((p.conditions?.users as { excludeGroups?: string[] } | undefined)?.excludeGroups?.length ?? 0);
const describe = (p: CaPolicy) => `Conditional Access "${p.displayName}" (${p.state}${exclusions(p) ? `, ${exclusions(p)} exclusion(s) — keep these to break-glass accounts only` : ""})`;

/** Evaluate CA-based controls: pass when an enabled policy does it, warn when only report-only does. */
function caCheck(s: M365Snapshot, matches: (p: CaPolicy) => boolean, what: string, viaSecurityDefaults = true): Outcome {
  if (viaSecurityDefaults && s.securityDefaults.ok && s.securityDefaults.data.isEnabled) return { status: "pass", summary: `Security defaults are on, which ${what}.`, evidence: ["Security defaults: enabled"] };
  const ca = unavailable(s.conditionalAccess);
  if (ca) return ca;
  const policies = (s.conditionalAccess as { data: CaPolicy[] }).data;
  const on = policies.filter((p) => enabled(p) && matches(p));
  if (on.length) return { status: "pass", summary: `Enforced by Conditional Access.`, evidence: on.map(describe) };
  const trial = policies.filter((p) => reportOnly(p) && matches(p));
  if (trial.length) return { status: "warn", summary: `A matching policy exists but is in report-only mode, so nothing is enforced yet.`, evidence: trial.map(describe) };
  return { status: "fail", summary: `No enabled policy ${what}.`, evidence: [`${policies.length} Conditional Access policies reviewed; security defaults are ${s.securityDefaults.ok ? (s.securityDefaults.data.isEnabled ? "on" : "off") : "unknown"}.`] };
}

const CA_STEPS = (policy: string) => [
  "Sign in to the Microsoft Entra admin center (entra.microsoft.com) as a Conditional Access Administrator.",
  "Go to Protection → Conditional Access → Policies → New policy (or start from the matching Microsoft template).",
  policy,
  "Exclude only your two emergency (break-glass) accounts, set the policy to Report-only, check the sign-in impact for a few days, then switch it On.",
];

export const M365_CHECKS: Check[] = [
  // ─── Identity ────────────────────────────────────────────────────────────
  {
    id: "m365.legacy_auth_blocked",
    area: "identity",
    title: "Legacy authentication is blocked",
    severity: "critical",
    references: ["CISA SCuBA MS.AAD.1.1v1", "CIS M365 Foundations: block legacy authentication (Conditional Access)"],
    why: "Old protocols (POP, IMAP, SMTP AUTH, ActiveSync basic auth, older Office clients) cannot do MFA. Password-spraying attacks use them precisely to get around MFA.",
    howToFix: CA_STEPS("Users: All users. Target resources: All cloud apps. Conditions → Client apps: Exchange ActiveSync clients and Other clients. Grant: Block access."),
    evaluate: (s) => caCheck(s, (p) => blocks(p) && allUsers(p) && (p.conditions?.clientAppTypes ?? []).includes("exchangeActiveSync") && (p.conditions?.clientAppTypes ?? []).includes("other"), "blocks legacy authentication for all users"),
  },
  {
    id: "m365.mfa_all_users",
    area: "identity",
    title: "MFA is required for every user",
    severity: "critical",
    references: ["CISA SCuBA MS.AAD.3.2v1", "CIS M365 Foundations: MFA for all users"],
    why: "Stolen or guessed passwords are the most common way into Microsoft 365. MFA stops the vast majority of these account takeovers.",
    howToFix: CA_STEPS("Users: All users. Target resources: All cloud apps. Grant: Require multifactor authentication (or an authentication strength)."),
    evaluate: (s) => caCheck(s, (p) => requiresMfa(p) && allUsers(p) && allApps(p), "requires MFA for all users on all apps"),
  },
  {
    id: "m365.mfa_phishing_resistant_admins",
    area: "identity",
    title: "Administrators must use phishing-resistant MFA",
    severity: "high",
    references: ["CISA SCuBA MS.AAD.3.6v1", "CISA SCuBA MS.AAD.3.1v1"],
    why: "Attackers phish admins with real-time proxy pages (adversary-in-the-middle) that relay one-time codes and push approvals. FIDO2 keys, Windows Hello for Business and certificate-based sign-in cannot be relayed.",
    howToFix: [
      ...CA_STEPS("Users: Directory roles → Global Administrator and the other privileged roles. Target resources: All cloud apps. Grant: Require authentication strength → Phishing-resistant MFA.").slice(0, 3),
      "Register FIDO2 security keys or Windows Hello for Business for every admin first (Protection → Authentication methods), then turn the policy on.",
    ],
    evaluate: (s) => caCheck(s, (p) => coversAdmins(p) && p.grantControls?.authenticationStrength?.id === PHISHING_RESISTANT_STRENGTH, "requires phishing-resistant MFA for administrators", false),
  },
  {
    id: "m365.mfa_registration",
    area: "identity",
    title: "Every user has registered for MFA",
    severity: "high",
    references: ["CIS M365 Foundations: MFA registered for all users"],
    requires: "Entra ID P1",
    why: "A policy that requires MFA does not protect accounts that never registered a method — and an attacker with the password can register their own.",
    howToFix: [
      "Entra admin center → Protection → Authentication methods → User registration details: filter on 'MFA capable = No'.",
      "Ask each listed user to register at https://aka.ms/mysecurityinfo (start with administrators).",
      "Turn on the registration campaign (Authentication methods → Registration campaign) to prompt users at sign-in.",
    ],
    evaluate: (s) => {
      const u = unavailable(s.registration);
      if (u) return u;
      const rows = (s.registration as { data: Array<{ userPrincipalName: string; isAdmin: boolean; isMfaRegistered: boolean }> }).data;
      const admins = rows.filter((r) => r.isAdmin && !r.isMfaRegistered);
      const users = rows.filter((r) => !r.isAdmin && !r.isMfaRegistered);
      if (admins.length === 0 && users.length === 0) return { status: "pass", summary: `All ${rows.length} users have registered an MFA method.` };
      return {
        status: admins.length > 0 || users.length / Math.max(rows.length, 1) > 0.05 ? "fail" : "warn",
        summary: `${admins.length} administrator(s) and ${users.length} user(s) have no MFA method registered.`,
        evidence: list([...admins.map((r) => `Admin: ${r.userPrincipalName}`), ...users.map((r) => r.userPrincipalName)]),
      };
    },
  },
  {
    id: "m365.risk_policies",
    area: "identity",
    title: "High-risk users and sign-ins are blocked",
    severity: "high",
    references: ["CISA SCuBA MS.AAD.2.1v1", "CISA SCuBA MS.AAD.2.3v1"],
    requires: "Entra ID P2",
    why: "Microsoft flags leaked credentials and impossible-travel or anonymous-IP sign-ins as risky. Blocking (or forcing a secure password reset) stops attackers who already have a valid password.",
    howToFix: CA_STEPS("Create two policies for All users / All cloud apps: (1) Conditions → User risk: High → Grant: Block (or require password change + MFA); (2) Conditions → Sign-in risk: High → Grant: Block."),
    evaluate: (s) => {
      const ca = unavailable(s.conditionalAccess);
      if (ca) return ca;
      const ps = (s.conditionalAccess as { data: CaPolicy[] }).data.filter(enabled);
      const user = ps.find((p) => (p.conditions?.userRiskLevels ?? []).includes("high") && (blocks(p) || controls(p).includes("passwordChange")));
      const signIn = ps.find((p) => (p.conditions?.signInRiskLevels ?? []).includes("high") && (blocks(p) || requiresMfa(p)));
      if (user && signIn) return { status: "pass", summary: "Both user-risk and sign-in-risk policies are enforced.", evidence: [describe(user), describe(signIn)] };
      if (user || signIn) return { status: "warn", summary: `Only the ${user ? "user-risk" : "sign-in-risk"} policy is enforced.`, evidence: [describe((user ?? signIn)!)] };
      return { status: "fail", summary: "No enabled policy acts on high user or sign-in risk." };
    },
  },
  {
    id: "m365.global_admin_count",
    area: "identity",
    title: "Between 2 and 8 Global Administrators",
    severity: "medium",
    references: ["CISA SCuBA MS.AAD.7.1v1", "CIS M365 Foundations: 2–4 global admins"],
    why: "One Global Admin is a single point of failure; many multiply the chance one is phished. Most admin work needs a narrower role.",
    howToFix: [
      "Entra admin center → Identity → Roles & admins → Global Administrator → review the assignments.",
      "Keep two emergency accounts plus the few people who truly need it; move everyone else to least-privilege roles (User, Exchange, Security Administrator…).",
    ],
    evaluate: (s) => {
      const u = unavailable(s.privilegedRoles);
      if (u) return u;
      const ga = (s.privilegedRoles as { data: Array<{ roleTemplateId: string; members: Array<{ userPrincipalName: string }> }> }).data.find((r) => r.roleTemplateId === GLOBAL_ADMIN_ROLE);
      const n = ga?.members.length ?? 0;
      const evidence = (ga?.members ?? []).map((m) => m.userPrincipalName);
      if (n >= 2 && n <= 8) return { status: "pass", summary: `${n} Global Administrators.`, evidence };
      return { status: n === 0 ? "unknown" : "fail", summary: n < 2 ? `Only ${n} Global Administrator — losing it locks you out.` : `${n} Global Administrators — too many.`, evidence: list(evidence) };
    },
  },
  {
    id: "m365.admins_cloud_only",
    area: "identity",
    title: "Admin accounts are cloud-only",
    severity: "medium",
    references: ["CISA SCuBA MS.AAD.7.3v1"],
    why: "An admin synced from on-premises Active Directory can be taken over from the local network, turning an on-premises breach into a full Microsoft 365 compromise.",
    howToFix: [
      "Create separate cloud-only admin accounts (name@tenant.onmicrosoft.com) for each administrator.",
      "Move the privileged role assignments to those accounts and remove them from the synced accounts.",
    ],
    evaluate: (s) => {
      const u = unavailable(s.privilegedRoles);
      if (u) return u;
      const synced = new Set<string>();
      for (const r of (s.privilegedRoles as { data: Array<{ roleName: string; members: Array<{ userPrincipalName: string; onPremisesSyncEnabled?: boolean | null }> }> }).data) {
        for (const m of r.members) if (m.onPremisesSyncEnabled) synced.add(`${m.userPrincipalName} (${r.roleName})`);
      }
      return synced.size === 0 ? { status: "pass", summary: "No privileged role is held by an account synced from on-premises." } : { status: "fail", summary: `${synced.size} privileged assignment(s) belong to synced accounts.`, evidence: list([...synced]) };
    },
  },
  {
    id: "m365.user_app_registration",
    area: "identity",
    title: "Users cannot register applications",
    severity: "medium",
    references: ["CISA SCuBA MS.AAD.5.1v1", "CIS M365 Foundations: users cannot register applications"],
    why: "Attackers who phish one user can register an app with long-lived credentials as a persistent backdoor that survives password resets.",
    howToFix: ["Entra admin center → Identity → Users → User settings → 'Users can register applications' → No → Save."],
    evaluate: (s) => {
      const u = unavailable(s.authorizationPolicy);
      if (u) return u;
      const v = (s.authorizationPolicy as { data: { allowedToCreateApps: boolean | null } }).data.allowedToCreateApps;
      return v === false ? { status: "pass", summary: "Only admins can register applications." } : { status: "fail", summary: "Any user can register applications." };
    },
  },
  {
    id: "m365.user_consent",
    area: "identity",
    title: "Users cannot consent to apps on their own",
    severity: "high",
    references: ["CISA SCuBA MS.AAD.5.2v1", "CIS M365 Foundations: user consent to apps not allowed"],
    why: "Consent phishing tricks a user into granting a malicious app access to their mail and files — no password needed, and MFA does not help.",
    howToFix: [
      "Entra admin center → Identity → Applications → Enterprise applications → Consent and permissions → User consent settings → 'Do not allow user consent'.",
      "Turn on the admin consent workflow (Admin consent settings) so users can request apps for review.",
    ],
    evaluate: (s) => {
      const u = unavailable(s.authorizationPolicy);
      if (u) return u;
      const policies = (s.authorizationPolicy as { data: { permissionGrantPolicies: string[] } }).data.permissionGrantPolicies.filter((p) => p.startsWith("ManagePermissionGrantsForSelf."));
      if (policies.length === 0) return { status: "pass", summary: "Users cannot grant apps access on their own." };
      if (policies.every((p) => p.endsWith("microsoft-user-default-low"))) return { status: "warn", summary: "Users may consent to low-risk permissions from verified publishers.", evidence: policies };
      return { status: "fail", summary: "Users can consent to any app.", evidence: policies };
    },
  },
  {
    id: "m365.guest_access_restricted",
    area: "identity",
    title: "Guest users have restricted directory access",
    severity: "medium",
    references: ["CISA SCuBA MS.AAD.8.1v1", "CIS M365 Foundations: guest user access restricted"],
    why: "Guests with member-level access can list every user, group and admin — a ready-made target list for phishing.",
    howToFix: ["Entra admin center → Identity → External Identities → External collaboration settings → Guest user access → 'Guest user access is restricted to properties and memberships of their own directory objects' → Save."],
    evaluate: (s) => {
      const u = unavailable(s.authorizationPolicy);
      if (u) return u;
      const id = (s.authorizationPolicy as { data: { guestUserRoleId: string | null } }).data.guestUserRoleId;
      return id && GUEST_RESTRICTED.has(id) ? { status: "pass", summary: "Guest access to the directory is restricted." } : { status: "fail", summary: "Guests have the same directory access as members." };
    },
  },
  {
    id: "m365.guest_invites",
    area: "identity",
    title: "Only admins and guest inviters can invite guests",
    severity: "low",
    references: ["CISA SCuBA MS.AAD.8.2v1"],
    why: "When anyone can invite guests, outsiders end up with access to Teams, SharePoint and files without any review.",
    howToFix: ["Entra admin center → Identity → External Identities → External collaboration settings → Guest invite settings → 'Only users assigned to specific admin roles can invite guest users' → Save."],
    evaluate: (s) => {
      const u = unavailable(s.authorizationPolicy);
      if (u) return u;
      const v = (s.authorizationPolicy as { data: { allowInvitesFrom: string | null } }).data.allowInvitesFrom;
      return v === "adminsAndGuestInviters" || v === "none" ? { status: "pass", summary: `Guest invitations: ${v}.` } : { status: "fail", summary: `Guest invitations allowed from: ${v ?? "unknown"}.` };
    },
  },
  {
    id: "m365.password_expiration",
    area: "identity",
    title: "Passwords do not expire",
    severity: "low",
    references: ["CISA SCuBA MS.AAD.6.1v1", "CIS M365 Foundations: password expiration set to never"],
    why: "Forced periodic changes push people to predictable passwords (Spring2025!, Summer2025!). With MFA in place, current guidance (NIST SP 800-63B) is not to expire passwords.",
    howToFix: ["Microsoft 365 admin center → Settings → Org settings → Security & privacy → Password expiration policy → 'Set passwords to never expire' → Save."],
    evaluate: (s) => {
      const u = unavailable(s.domains);
      if (u) return u;
      const expiring = (s.domains as { data: Array<{ id: string; isVerified: boolean; passwordValidityPeriodInDays: number | null }> }).data.filter((d) => d.isVerified && d.passwordValidityPeriodInDays !== null && d.passwordValidityPeriodInDays < 2147483647);
      return expiring.length === 0 ? { status: "pass", summary: "Passwords are set never to expire." } : { status: "fail", summary: `Passwords expire on ${expiring.length} domain(s).`, evidence: expiring.map((d) => `${d.id}: every ${d.passwordValidityPeriodInDays} days`) };
    },
  },
  {
    id: "m365.risky_users",
    area: "identity",
    title: "No users are currently flagged as at risk",
    severity: "high",
    references: ["Microsoft Entra ID Protection"],
    requires: "Entra ID P2",
    why: "Microsoft flags accounts whose credentials leaked or that signed in from attacker infrastructure. Each one needs investigating now.",
    howToFix: [
      "Entra admin center → Protection → Identity Protection → Risky users.",
      "For each user: review the risky sign-ins, reset the password, revoke sessions (Users → user → Revoke sessions), then confirm compromised or dismiss the risk.",
    ],
    evaluate: (s) => {
      const u = unavailable(s.riskyUsers);
      if (u) return u;
      const r = (s.riskyUsers as { data: Array<{ userPrincipalName: string; riskLevel: string }> }).data;
      return r.length === 0 ? { status: "pass", summary: "No user is flagged as at risk." } : { status: "fail", summary: `${r.length} user(s) flagged as at risk.`, evidence: list(r.map((x) => `${x.userPrincipalName} (${x.riskLevel})`)) };
    },
  },

  // ─── Email ───────────────────────────────────────────────────────────────
  {
    id: "m365.inbox_rules_external_forwarding",
    area: "email",
    title: "No inbox rules forward mail outside the company",
    severity: "critical",
    references: ["CISA SCuBA MS.EXO.1.1v1 (automatic forwarding)", "Business email compromise (MITRE ATT&CK T1114.003)"],
    why: "After taking over a mailbox, attackers add a rule that quietly forwards mail (invoices, payment details) to themselves — it keeps working after the password is reset.",
    howToFix: [
      "For each rule listed: confirm with the user; if they did not create it, treat the account as compromised (reset password, revoke sessions, check sign-ins).",
      "Remove the rule: Exchange admin center → Recipients → Mailboxes → user, or in Outlook on the web → Settings → Mail → Rules.",
      "Block automatic external forwarding for everyone (see the 'External automatic forwarding is blocked' check).",
    ],
    evaluate: (s) => {
      const u = unavailable(s.inboxRules);
      if (u) return u;
      const internal = new Set(s.organization.ok ? s.organization.data.verifiedDomains : []);
      const { mailboxesScanned, rules } = (s.inboxRules as { data: { mailboxesScanned: number; rules: Array<{ user: string; name: string; enabled: boolean; forwardTo: string[] }> } }).data;
      const external = rules.filter((r) => r.enabled && r.forwardTo.some((a) => !internal.has(a.split("@")[1]?.toLowerCase() ?? "")));
      if (external.length === 0) return { status: "pass", summary: `No inbox rule forwards mail outside the company (${mailboxesScanned} mailboxes checked).` };
      return { status: "fail", summary: `${external.length} inbox rule(s) forward mail to outside addresses.`, evidence: list(external.map((r) => `${r.user}: "${r.name}" → ${r.forwardTo.join(", ")}`)) };
    },
  },
  {
    id: "m365.inbox_rules_hiding",
    area: "email",
    title: "No inbox rules that delete or hide incoming mail",
    severity: "high",
    references: ["Business email compromise (MITRE ATT&CK T1564.008)"],
    why: "Attackers create rules that delete or mark-as-read-and-move replies from the victim's contacts so the real owner never sees the conversation they hijacked.",
    howToFix: [
      "Review each rule with the mailbox owner; rules named with dots or single letters that delete or move mail to RSS Feeds / Archive are a classic sign of compromise.",
      "Remove unknown rules and investigate the account (password reset, revoke sessions, review sign-in logs).",
    ],
    evaluate: (s) => {
      const u = unavailable(s.inboxRules);
      if (u) return u;
      const rules = (s.inboxRules as { data: { rules: Array<{ user: string; name: string; enabled: boolean; delete: boolean; markAsRead: boolean; moveToFolder: string | null }> } }).data.rules;
      const hiding = rules.filter((r) => r.enabled && (r.delete || (r.markAsRead && r.moveToFolder)));
      return hiding.length === 0
        ? { status: "pass", summary: "No rule deletes or hides incoming mail." }
        : { status: "warn", summary: `${hiding.length} rule(s) delete or hide incoming mail — confirm each with its owner.`, evidence: list(hiding.map((r) => `${r.user}: "${r.name}" (${r.delete ? "deletes" : "marks read and moves"})`)) };
    },
  },
  {
    id: "m365.spf",
    area: "email",
    title: "SPF is published for every mail domain",
    severity: "high",
    references: ["CISA SCuBA MS.EXO.2.2v2", "CIS M365 Foundations: SPF records published"],
    why: "SPF tells receiving mail servers which servers may send for your domain. Without it, anyone can send convincing mail as your company.",
    howToFix: ["At your DNS host, publish a TXT record on each domain: v=spf1 include:spf.protection.outlook.com -all (add your other senders' includes before -all)."],
    evaluate: (s) => {
      const u = unavailable(s.mailDns);
      if (u) return u;
      const d = (s.mailDns as { data: Array<{ domain: string; spf: string[] }> }).data;
      if (d.length === 0) return { status: "pass", summary: "No custom mail domains (only onmicrosoft.com)." };
      const bad = d.filter((x) => x.spf.length !== 1 || /\+all\b/i.test(x.spf[0]!) || !/[-~]all\b/i.test(x.spf[0]!));
      return bad.length === 0 ? { status: "pass", summary: `SPF is correct on ${d.length} domain(s).` } : { status: "fail", summary: `SPF missing or weak on ${bad.length} domain(s).`, evidence: bad.map((x) => `${x.domain}: ${x.spf.length === 0 ? "no SPF record" : x.spf.length > 1 ? "more than one SPF record" : x.spf[0]}`) };
    },
  },
  {
    id: "m365.dkim",
    area: "email",
    title: "DKIM signing is set up",
    severity: "medium",
    references: ["CISA SCuBA MS.EXO.3.1v1", "CIS M365 Foundations: DKIM enabled"],
    why: "DKIM signs outgoing mail so receivers can prove it really came from you and was not changed — DMARC relies on it.",
    howToFix: [
      "Microsoft Defender portal → Email & collaboration → Policies & rules → Threat policies → Email authentication settings → DKIM.",
      "Select each domain, publish the two CNAME records it shows (selector1._domainkey and selector2._domainkey) at your DNS host, then turn on signing.",
    ],
    evaluate: (s) => {
      const u = unavailable(s.mailDns);
      if (u) return u;
      const d = (s.mailDns as { data: Array<{ domain: string; dkimSelectors: string[] }> }).data;
      const missing = d.filter((x) => x.dkimSelectors.length === 0);
      return missing.length === 0 ? { status: "pass", summary: d.length ? `DKIM selectors published on ${d.length} domain(s).` : "No custom mail domains." } : { status: "fail", summary: `No DKIM selector CNAMEs on ${missing.length} domain(s).`, evidence: missing.map((x) => x.domain) };
    },
  },
  {
    id: "m365.dmarc",
    area: "email",
    title: "DMARC rejects spoofed mail",
    severity: "high",
    references: ["CISA SCuBA MS.EXO.4.1v1", "CISA SCuBA MS.EXO.4.2v1", "CIS M365 Foundations: DMARC published"],
    why: "DMARC tells receivers what to do with mail that fails SPF/DKIM. With p=reject, spoofed invoices and CEO-fraud mail claiming to be from you are refused.",
    howToFix: [
      "Publish a TXT record at _dmarc.<domain>: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain> and watch the reports for a few weeks.",
      "Once legitimate senders all pass, change to p=reject.",
    ],
    evaluate: (s) => {
      const u = unavailable(s.mailDns);
      if (u) return u;
      const d = (s.mailDns as { data: Array<{ domain: string; dmarc: string[] }> }).data;
      if (d.length === 0) return { status: "pass", summary: "No custom mail domains." };
      const policy = (x: { dmarc: string[] }) => /\bp\s*=\s*(none|quarantine|reject)/i.exec(x.dmarc[0] ?? "")?.[1]?.toLowerCase() ?? null;
      const missing = d.filter((x) => !policy(x) || policy(x) === "none");
      const quarantine = d.filter((x) => policy(x) === "quarantine");
      const evidence = d.map((x) => `${x.domain}: ${x.dmarc[0] ?? "no DMARC record"}`);
      if (missing.length) return { status: "fail", summary: `DMARC missing or set to p=none on ${missing.length} domain(s).`, evidence };
      if (quarantine.length) return { status: "warn", summary: `DMARC is p=quarantine on ${quarantine.length} domain(s); move to p=reject.`, evidence };
      return { status: "pass", summary: `DMARC p=reject on all ${d.length} domain(s).`, evidence };
    },
  },
  {
    id: "m365.external_forwarding_policy",
    area: "email",
    title: "External automatic forwarding is blocked",
    severity: "high",
    references: ["CISA SCuBA MS.EXO.1.1v1", "CIS M365 Foundations: all forms of mail forwarding blocked"],
    why: "Blocking automatic forwarding to outside addresses for the whole organization stops data theft through forwarding rules even when a mailbox is compromised.",
    howToFix: [
      "Microsoft Defender portal → Email & collaboration → Policies & rules → Threat policies → Anti-spam → Anti-spam outbound policy (Default).",
      "Edit protection settings → Forwarding rules → Automatic forwarding rules: 'Off - Forwarding is disabled' → Save.",
      "Allow exceptions with a separate outbound policy scoped to the few mailboxes that really need it.",
      "(Microsoft exposes this only through Exchange Online PowerShell — Get-HostedOutboundSpamFilterPolicy | Select AutoForwardingMode — so confirm it there or in the portal.)",
    ],
    evaluate: () => ({ status: "manual", summary: "Check this setting in the Defender portal (not readable through Microsoft Graph)." }),
  },
  {
    id: "m365.audit_log",
    area: "email",
    title: "Unified audit logging is on",
    severity: "high",
    references: ["CISA SCuBA MS.EXO.17.1v1", "CIS M365 Foundations: audit log search enabled"],
    why: "Without the audit log there is no record of who read, forwarded or deleted mail — investigations of a compromise become guesswork.",
    howToFix: [
      "Microsoft Purview portal (purview.microsoft.com) → Solutions → Audit.",
      "If you see 'Start recording user and admin activity', select it. Recording starts within a few hours.",
      "(Exchange Online PowerShell: Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled should be True.)",
    ],
    evaluate: () => ({ status: "manual", summary: "Confirm in the Purview portal (not readable through Microsoft Graph)." }),
  },

  // ─── Apps ────────────────────────────────────────────────────────────────
  {
    id: "m365.risky_oauth_grants",
    area: "apps",
    title: "No third-party apps hold mail or file access granted by users",
    severity: "high",
    references: ["CISA SCuBA MS.AAD.5.2v1", "Consent phishing (MITRE ATT&CK T1528)"],
    why: "An app a user consented to keeps reading mail or files with its own token — even after the user's password changes. Malicious apps are a common post-phishing foothold.",
    howToFix: [
      "Entra admin center → Identity → Applications → Enterprise applications → select the app → Permissions: review who consented and to what.",
      "If the app is unknown or unneeded: Properties → 'Enabled for users to sign in?' → No, then delete the app (this revokes its tokens).",
      "Prevent new ones: see 'Users cannot consent to apps on their own'.",
    ],
    evaluate: (s) => {
      const u = unavailable(s.oauthGrants);
      if (u) return u;
      const grants = (s.oauthGrants as { data: Array<{ app: string; publisher: string | null; firstParty: boolean; consentType: string; scopes: string[] }> }).data;
      const risky = grants.filter((g) => !g.firstParty && g.scopes.some((sc) => HIGH_IMPACT_SCOPES.has(sc.toLowerCase())));
      const byUser = risky.filter((g) => g.consentType === "Principal");
      const evidence = list(risky.map((g) => `${g.app}${g.publisher ? ` (${g.publisher})` : ""} — ${g.consentType === "Principal" ? "consented by a user" : "admin consent for all users"}: ${g.scopes.filter((sc) => HIGH_IMPACT_SCOPES.has(sc.toLowerCase())).join(", ")}`));
      if (risky.length === 0) return { status: "pass", summary: "No third-party app holds mail, file or directory write access." };
      return byUser.length ? { status: "fail", summary: `${byUser.length} user-consented third-party app grant(s) with mail/file access.`, evidence } : { status: "warn", summary: `${risky.length} admin-approved third-party app(s) hold mail/file access — confirm they are still needed.`, evidence };
    },
  },
];

const WEIGHT: Record<M365Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function evaluateM365(snapshot: M365Snapshot): M365CheckResult[] {
  return M365_CHECKS.map(({ evaluate, ...def }) => {
    let out: Outcome;
    try {
      out = evaluate(snapshot);
    } catch (err) {
      out = { status: "unknown", summary: "The check could not be evaluated.", evidence: [err instanceof Error ? err.message : String(err)] };
    }
    return { ...def, status: out.status, summary: out.summary, evidence: out.evidence ?? [] };
  });
}

/** Severity-weighted share of graded checks that pass (warn counts half); unknown / manual excluded. */
export function scoreM365(results: M365CheckResult[]): { score: number; counts: Record<M365CheckStatus, number> } {
  const counts: Record<M365CheckStatus, number> = { pass: 0, fail: 0, warn: 0, unknown: 0, manual: 0 };
  let got = 0;
  let max = 0;
  for (const r of results) {
    counts[r.status]++;
    if (r.status === "pass" || r.status === "fail" || r.status === "warn") {
      max += WEIGHT[r.severity];
      got += r.status === "pass" ? WEIGHT[r.severity] : r.status === "warn" ? WEIGHT[r.severity] / 2 : 0;
    }
  }
  return { score: max === 0 ? 0 : Math.round((got / max) * 100), counts };
}

