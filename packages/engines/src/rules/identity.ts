import type { DetectionRuleInput } from "../detection/types.js";

/** Bloody built-in identity (ITDR) detections. Bloody-authored. */

const authFailure = { detection: { auth: { category: "authentication" }, failed: [{ outcome: "failure" }, { "identity.outcome": "failure" }] }, condition: "auth and failed" };
const authSuccess = { detection: { auth: { category: "authentication" }, ok: [{ outcome: "success" }, { "identity.outcome": "success" }] }, condition: "auth and ok" };

const signIn = (principal: string, outcome: "success" | "failure", sourceIp: string, offsetSeconds: number, geo?: { country: string; city: string; lat: number; lon: number }) => ({
  category: "authentication",
  source: { kind: "identity", product: "entra-id" },
  eventType: "sign_in",
  outcome,
  offsetSeconds,
  identity: { provider: "entra-id", principal, sourceIp, outcome, ...(geo ? { geo } : {}) },
});

const PARIS = { country: "FR", city: "Paris", lat: 48.8566, lon: 2.3522 };
const LYON = { country: "FR", city: "Lyon", lat: 45.764, lon: 4.8357 };
const SINGAPORE = { country: "SG", city: "Singapore", lat: 1.3521, lon: 103.8198 };

export const PASSWORD_SPRAY: DetectionRuleInput = {
  kind: "threshold",
  id: "bloody-itdr-password-spray",
  name: "Password spraying from a single source",
  description: "Failed sign-ins against 10 or more distinct accounts from one source address within 15 minutes — a few passwords tried across many accounts to stay under lockout thresholds.",
  version: 1,
  severity: "high",
  confidence: 0.8,
  attack: [{ id: "T1110.003", name: "Password Spraying", tactic: "credential-access" }],
  tags: ["itdr", "identity"],
  author: "Bloody Detection Engineering",
  falsePositives: ["Shared egress (VPN concentrator, proxy) with many users mistyping passwords — tune per source IP."],
  filter: authFailure,
  groupBy: ["identity.sourceIp"],
  distinctField: "identity.principal",
  threshold: 10,
  windowSeconds: 900,
  cooldownSeconds: 900,
  tests: [
    {
      name: "12 accounts from one address",
      expect: "match",
      expectedMatches: 1,
      events: Array.from({ length: 12 }, (_, i) => signIn(`user${i}@contoso.example`, "failure", "203.0.113.50", i * 20)),
    },
    {
      name: "one account hammered (brute force, not spray)",
      expect: "no_match",
      events: Array.from({ length: 12 }, (_, i) => signIn("alice@contoso.example", "failure", "203.0.113.50", i * 20)),
    },
    {
      name: "accounts spread across sources",
      expect: "no_match",
      events: Array.from({ length: 12 }, (_, i) => signIn(`user${i}@contoso.example`, "failure", `198.51.100.${i + 1}`, i * 20)),
    },
  ],
};

export const IMPOSSIBLE_TRAVEL: DetectionRuleInput = {
  kind: "sequence",
  id: "bloody-itdr-impossible-travel",
  name: "Impossible travel between successful sign-ins",
  description: "Two successful sign-ins by the same identity from locations further apart than physically reachable in the elapsed time (> 900 km/h, > 500 km) — a strong sign of credential or session-token theft.",
  version: 1,
  severity: "high",
  confidence: 0.7,
  attack: [{ id: "T1078.004", name: "Cloud Accounts", tactic: "initial-access" }],
  tags: ["itdr", "identity", "geo"],
  author: "Bloody Detection Engineering",
  falsePositives: ["Corporate VPN / cloud proxies that relocate egress — add their ranges to a suppression."],
  by: ["identity.principal"],
  windowSeconds: 4 * 3600,
  steps: [
    { name: "sign-in", filter: authSuccess },
    { name: "distant sign-in", filter: authSuccess, constraints: [{ type: "geo_velocity", maxKmh: 900, minDistanceKm: 500, fallbackCountryChange: true }] },
  ],
  tests: [
    { name: "Paris then Singapore 30 minutes later", expect: "match", expectedMatches: 1, events: [signIn("bob@contoso.example", "success", "192.0.2.10", 0, PARIS), signIn("bob@contoso.example", "success", "203.0.113.9", 1800, SINGAPORE)] },
    { name: "Paris then Lyon 3 hours later", expect: "no_match", events: [signIn("bob@contoso.example", "success", "192.0.2.10", 0, PARIS), signIn("bob@contoso.example", "success", "192.0.2.77", 3 * 3600, LYON)] },
    { name: "different users are not compared", expect: "no_match", events: [signIn("bob@contoso.example", "success", "192.0.2.10", 0, PARIS), signIn("carol@contoso.example", "success", "203.0.113.9", 600, SINGAPORE)] },
  ],
};

export const BRUTE_FORCE_THEN_SUCCESS: DetectionRuleInput = {
  kind: "sequence",
  id: "bloody-itdr-bruteforce-success",
  name: "Brute force followed by successful sign-in",
  description: "Five or more failed sign-ins for one account followed by a success within 15 minutes — the guessing attempt probably worked.",
  version: 1,
  severity: "high",
  confidence: 0.8,
  attack: [{ id: "T1110.001", name: "Password Guessing", tactic: "credential-access" }, { id: "T1078", name: "Valid Accounts", tactic: "initial-access" }],
  tags: ["itdr", "identity"],
  author: "Bloody Detection Engineering",
  falsePositives: ["Users who forgot a recently changed password and then succeed."],
  by: ["identity.principal"],
  windowSeconds: 900,
  steps: [
    { name: "repeated failures", filter: authFailure, minCount: 5 },
    { name: "success", filter: authSuccess },
  ],
  tests: [
    {
      name: "6 failures then success",
      expect: "match",
      expectedMatches: 1,
      events: [...Array.from({ length: 6 }, (_, i) => signIn("dave@contoso.example", "failure", "203.0.113.66", i * 10)), signIn("dave@contoso.example", "success", "203.0.113.66", 90)],
    },
    {
      name: "3 failures then success",
      expect: "no_match",
      events: [...Array.from({ length: 3 }, (_, i) => signIn("dave@contoso.example", "failure", "203.0.113.66", i * 10)), signIn("dave@contoso.example", "success", "203.0.113.66", 60)],
    },
    {
      name: "success long after failures",
      expect: "no_match",
      events: [...Array.from({ length: 6 }, (_, i) => signIn("dave@contoso.example", "failure", "203.0.113.66", i * 10)), signIn("dave@contoso.example", "success", "203.0.113.66", 3600)],
    },
  ],
};

export const NEW_ADMIN_ACCOUNT: DetectionRuleInput = {
  kind: "sigma",
  id: "bloody-itdr-new-admin-account",
  name: "New administrative account or privileged role assignment",
  description: "An account was added to a privileged directory group, granted an administrative IdP role, or created with privileged rights — a common persistence step after compromise.",
  version: 1,
  severity: "high",
  confidence: 0.65,
  attack: [
    { id: "T1136", name: "Create Account", tactic: "persistence" },
    { id: "T1098", name: "Account Manipulation", tactic: "persistence" },
  ],
  tags: ["itdr", "identity", "persistence"],
  author: "Bloody Detection Engineering",
  falsePositives: ["Planned administrator onboarding (correlate with change tickets)."],
  sigma: String.raw`
title: New administrative account or privileged role assignment
id: acfd6457-0e82-4b0b-90f0-36a1a5ddaccd
status: stable
author: Bloody Detection Engineering
logsource:
  product: windows
  service: security
detection:
  directory_privileged_group_add:
    EventID:
      - 4728
      - 4732
      - 4756
    labels.targetGroup|contains:
      - 'admins'
      - 'administrators'
      - 'account operators'
      - 'backup operators'
  idp_admin_role_assignment:
    eventType|contains:
      - 'role_assign'
      - 'add member to role'
      - 'admin_role_grant'
    labels.role|contains:
      - 'admin'
      - 'privileged'
  privileged_account_created:
    eventType:
      - 'account.created'
      - 'user.created'
      - 'user_created'
    identity.privileged: true
  condition: 1 of them
level: high
tags:
  - attack.persistence
  - attack.t1098
`,
  tests: [
    {
      name: "user added to local Administrators",
      expect: "match",
      events: [{ asset: { hostname: "dc-01", os: "Windows Server 2022" }, category: "identity", eventType: "group_member_added", user: { name: "eve", domain: "CORP" }, labels: { eventId: "4732", targetGroup: "Administrators" } }],
    },
    {
      name: "IdP global administrator role granted",
      expect: "match",
      events: [{ category: "identity", source: { kind: "identity", product: "entra-id" }, eventType: "role_assigned", identity: { provider: "entra-id", principal: "mallory@contoso.example" }, labels: { role: "Global Administrator" } }],
    },
    {
      name: "privileged account created",
      expect: "match",
      events: [{ category: "identity", eventType: "user.created", identity: { provider: "okta", principal: "svc-backup", privileged: true } }],
    },
    {
      name: "standard user created",
      expect: "no_match",
      events: [{ category: "identity", eventType: "user.created", identity: { provider: "okta", principal: "new.hire", privileged: false } }],
    },
    {
      name: "added to a non-privileged group",
      expect: "no_match",
      events: [{ asset: { hostname: "dc-01", os: "Windows Server 2022" }, category: "identity", eventType: "group_member_added", labels: { eventId: "4732", targetGroup: "Remote Desktop Users" } }],
    },
  ],
};

export const IDENTITY_RULES: DetectionRuleInput[] = [PASSWORD_SPRAY, IMPOSSIBLE_TRAVEL, BRUTE_FORCE_THEN_SUCCESS, NEW_ADMIN_ACCOUNT];
