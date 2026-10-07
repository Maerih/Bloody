import { describe, expect, it } from "vitest";
import nodemailer from "nodemailer";
import { channel, FakeClock, FakeHttp, FakeSecrets, ORG_A, RecordingSyslogTransport, sequentialIds, TENANT } from "../test-support/fixtures.js";
import { DeliveryError, SsrfBlockedError } from "../util/errors.js";
import { EmailSender, composeEmail } from "./email.js";
import { NodeHttpTransport } from "./http.js";
import { InAppSender, InMemoryInAppStore } from "./in-app.js";
import { ChannelRegistry } from "./registry.js";
import { buildSlackPayload, SlackSender } from "./slack.js";
import { assertSafeUrl, checkAddress, checkHostname, createGuardedLookup, type LookupFunction } from "./ssrf.js";
import { buildSyslogMessage, escapeSdValue, formatRfc5424, SyslogSender, truncateUtf8 } from "./syslog.js";
import { buildTeamsPayload, TeamsSender } from "./teams.js";
import { DEFAULT_BRANDING, resolveBranding, type NotificationMessage } from "./types.js";
import { generateWebhookSecret, signWebhookPayload, verifyWebhookSignature, WebhookSender } from "./webhook.js";

const message: NotificationMessage = {
  id: "9d2f0d7e-31a5-4c43-9a51-5f8f3b0c1a01",
  tenantId: TENANT,
  organizationId: ORG_A,
  organizationName: "Acme <Corp>",
  event: "incident.created",
  severity: "critical",
  subject: "[CRITICAL] Incident #42: Ransomware on <FIN-WS-042>",
  text: "A **critical** incident was opened.\n\n- Host: FIN-WS-042 <script>alert(1)</script>\n- See https://app.bloody.example/incidents/42",
  facts: [
    { label: "Risk score", value: "91" },
    { label: "Assignee", value: "<!channel> unassigned" },
  ],
  link: { url: "https://app.bloody.example/incidents/42", label: "Open incident" },
  occurredAt: "2026-10-07T11:58:00.000Z",
  dedupKey: "incident:42",
  data: { incident: { id: "inc-42", number: 42 } },
  origin: { kind: "automation_rule", id: "rule-1", name: "Critical incidents to SOC" },
};

describe("SSRF guard", () => {
  it("blocks metadata, link-local, loopback, private and reserved ranges", () => {
    for (const ip of ["169.254.169.254", "127.0.0.1", "10.1.2.3", "172.16.5.4", "192.168.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fc00::5", "fd00:ec2::254", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "192.0.2.10"]) {
      expect(checkAddress(ip).blocked, ip).toBe(true);
    }
    for (const ip of ["93.184.216.34", "2606:4700:4700::1111", "8.8.8.8"]) expect(checkAddress(ip).blocked, ip).toBe(false);
    // Private allowed (syslog) — metadata still blocked.
    expect(checkAddress("10.0.0.5", { allowPrivateNetworks: true }).blocked).toBe(false);
    expect(checkAddress("169.254.169.254", { allowPrivateNetworks: true, allowLoopback: true }).blocked).toBe(true);
  });

  it("validates URLs statically (scheme, credentials, internal names, allow-lists)", () => {
    expect(() => assertSafeUrl("http://example.com/hook")).toThrow(SsrfBlockedError);
    expect(() => assertSafeUrl("https://user:pw@example.com/")).toThrow(/credentials/);
    expect(() => assertSafeUrl("https://169.254.169.254/latest/meta-data")).toThrow(/forbidden range/);
    expect(() => assertSafeUrl("https://[::1]/")).toThrow(/loopback/);
    expect(() => assertSafeUrl("https://0x7f000001/")).toThrow(SsrfBlockedError);
    expect(() => assertSafeUrl("https://metadata.google.internal/")).toThrow(SsrfBlockedError);
    expect(() => assertSafeUrl("https://intranet/")).toThrow(/internal name/);
    expect(assertSafeUrl("https://hooks.example.com/x").hostname).toBe("hooks.example.com");
    expect(checkHostname("evil.com", { allowedHostSuffixes: ["hooks.slack.com"] }).blocked).toBe(true);
    expect(checkHostname("hooks.slack.com.evil.com", { allowedHostSuffixes: ["hooks.slack.com"] }).blocked).toBe(true);
    expect(checkHostname("hooks.slack.com", { allowedHostSuffixes: ["hooks.slack.com"] }).blocked).toBe(false);
  });

  it("rejects DNS answers pointing at blocked ranges (rebinding defence)", async () => {
    const fakeDns: LookupFunction = (_host, _opts, cb) => cb(null, [{ address: "93.184.216.34", family: 4 }, { address: "169.254.169.254", family: 4 }]);
    const guarded = createGuardedLookup({}, fakeDns);
    const err = await new Promise<unknown>((resolve) => guarded("rebind.example.com", {}, (e) => resolve(e)));
    expect(err).toBeInstanceOf(SsrfBlockedError);
    const okDns: LookupFunction = (_host, _opts, cb) => cb(null, [{ address: "93.184.216.34", family: 4 }]);
    const res = await new Promise<string>((resolve) => createGuardedLookup({}, okDns)("ok.example.com", {}, (_e, a) => resolve(a as string)));
    expect(res).toBe("93.184.216.34");
  });

  it("the Node transport refuses blocked literal addresses before connecting", async () => {
    const t = new NodeHttpTransport();
    await expect(t.request({ url: "https://10.0.0.8/hook", method: "POST", headers: {}, body: "{}" })).rejects.toBeInstanceOf(SsrfBlockedError);
    await expect(t.request({ url: "https://[fd00:ec2::254]/", method: "POST", headers: {}, body: "{}" })).rejects.toBeInstanceOf(SsrfBlockedError);
  });
});

describe("webhook channel", () => {
  const secrets = new FakeSecrets({ "hook-url": "https://hooks.customer.example/bloody", "hook-secret": "whsec_test_secret" });

  it("signs the JSON body with HMAC-SHA256 over timestamp.body", async () => {
    const http = new FakeHttp();
    const clock = new FakeClock("2026-10-07T12:00:00Z");
    const sender = new WebhookSender({ http, secrets, clock });
    const ch = channel("webhook", { urlRef: "hook-url", secretRef: "hook-secret" });
    const res = await sender.send(ch, message);
    expect(res.ok).toBe(true);
    const req = http.requests[0]!;
    expect(req.url).toBe("https://hooks.customer.example/bloody");
    expect(req.headers["X-Bloody-Timestamp"]).toBe(String(Date.parse("2026-10-07T12:00:00Z") / 1000));
    expect(req.headers["X-Bloody-Signature"]).toMatch(/^sha256=[0-9a-f]{64}$/);
    expect(req.headers["X-Bloody-Event"]).toBe("incident.created");
    expect(verifyWebhookSignature({ secret: "whsec_test_secret", signature: req.headers["X-Bloody-Signature"], timestamp: req.headers["X-Bloody-Timestamp"], body: req.body, now: clock.now() })).toBe(true);
    expect(verifyWebhookSignature({ secret: "wrong", signature: req.headers["X-Bloody-Signature"], timestamp: req.headers["X-Bloody-Timestamp"], body: req.body, now: clock.now() })).toBe(false);
    expect(verifyWebhookSignature({ secret: "whsec_test_secret", signature: req.headers["X-Bloody-Signature"], timestamp: req.headers["X-Bloody-Timestamp"], body: req.body + " ", now: clock.now() })).toBe(false);
    // Replay outside the tolerance window is refused.
    expect(verifyWebhookSignature({ secret: "whsec_test_secret", signature: req.headers["X-Bloody-Signature"], timestamp: req.headers["X-Bloody-Timestamp"], body: req.body, now: new Date("2026-10-07T12:10:00Z") })).toBe(false);
    const body = JSON.parse(req.body);
    expect(body).toMatchObject({ event: "incident.created", severity: "critical", tenantId: TENANT, organizationId: ORG_A, data: { incident: { number: 42 } } });
    expect(signWebhookPayload("k", 1, "{}")).toBe(signWebhookPayload("k", 1, "{}"));
    expect(generateWebhookSecret()).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
  });

  it("requires a signing secret by default and rejects reserved headers", () => {
    const sender = new WebhookSender({ http: new FakeHttp(), secrets });
    expect(sender.validateConfig({ url: "https://x.example/h" }).ok).toBe(false);
    expect(sender.validateConfig({ url: "https://x.example/h", secretRef: "s", headers: { "X-Bloody-Signature": "forged" } }).ok).toBe(false);
    expect(sender.validateConfig({ url: "https://x.example/h", secretRef: "s", headers: { "X-Team": "soc" } }).ok).toBe(true);
    expect(sender.validateConfig({ url: "https://x.example/h", urlRef: "y", secretRef: "s" }).ok).toBe(false);
  });

  it("classifies HTTP failures as retryable or permanent", async () => {
    const sender5xx = new WebhookSender({ http: new FakeHttp([{ status: 503, headers: {}, body: "busy" }]), secrets });
    await expect(sender5xx.send(channel("webhook", { urlRef: "hook-url", secretRef: "hook-secret" }), message)).rejects.toMatchObject({ retryable: true, status: 503 });
    const sender4xx = new WebhookSender({ http: new FakeHttp([{ status: 404, headers: {}, body: "nope" }]), secrets });
    await expect(sender4xx.send(channel("webhook", { urlRef: "hook-url", secretRef: "hook-secret" }), message)).rejects.toMatchObject({ retryable: false });
    const redirect = new WebhookSender({ http: new FakeHttp([{ status: 302, headers: { location: "http://169.254.169.254/" }, body: "" }]), secrets });
    await expect(redirect.send(channel("webhook", { urlRef: "hook-url", secretRef: "hook-secret" }), message)).rejects.toThrow(/redirects are not followed/);
  });
});

describe("Slack channel", () => {
  it("builds a Block Kit payload with escaped content and a severity colour", () => {
    const payload = buildSlackPayload(message, DEFAULT_BRANDING, { mention: "here" }) as { text: string; attachments: { color: string; blocks: { type: string; text?: { text: string }; fields?: { text: string }[]; elements?: { url?: string }[] }[] }[] };
    expect(payload.text).toMatch(/^<!here> \[Critical\]/);
    expect(payload.text).toContain("&lt;FIN-WS-042&gt;");
    const att = payload.attachments[0]!;
    expect(att.color).toBe("#D03B3B");
    expect(att.blocks.map((b) => b.type)).toEqual(["header", "section", "section", "context", "actions"]);
    expect(att.blocks[1]!.text!.text).toContain("*critical*");
    expect(att.blocks[1]!.text!.text).toContain("&lt;script&gt;");
    expect(att.blocks[2]!.fields!.map((f) => f.text)).toContain("*Assignee*\n&lt;!channel&gt; unassigned");
    expect(att.blocks[4]!.elements![0]!.url).toBe("https://app.bloody.example/incidents/42");
  });

  it("only posts to Slack hosts", async () => {
    const http = new FakeHttp();
    const sender = new SlackSender({ http, secrets: new FakeSecrets({}) });
    expect(sender.validateConfig({ url: "https://evil.example.com/services/x" }).ok).toBe(false);
    expect(sender.validateConfig({ url: "not a url" }).ok).toBe(false);
    const ch = channel("slack", { url: "https://hooks.slack.com/services/T000/B000/XXXX" });
    await sender.send(ch, message);
    expect(http.requests[0]!.ssrf?.allowedHostSuffixes).toContain("hooks.slack.com");
  });
});

describe("Microsoft Teams channel", () => {
  it("builds an Adaptive Card message", () => {
    const payload = buildTeamsPayload(message, resolveBranding({ name: "Acme MSSP", primaryColor: "#0055AA" })) as {
      type: string;
      attachments: { contentType: string; content: { type: string; version: string; body: { type: string; text?: string; facts?: { title: string; value: string }[]; style?: string }[]; actions: { type: string; url: string }[] } }[];
    };
    expect(payload.type).toBe("message");
    const card = payload.attachments[0]!;
    expect(card.contentType).toBe("application/vnd.microsoft.card.adaptive");
    expect(card.content.type).toBe("AdaptiveCard");
    expect(card.content.version).toBe("1.4");
    expect(card.content.body[0]!.style).toBe("attention");
    const factSet = card.content.body.find((b) => b.type === "FactSet")!;
    expect(factSet.facts![0]).toEqual({ title: "Risk score", value: "91" });
    expect(card.content.actions[0]).toEqual({ type: "Action.OpenUrl", title: "Open incident", url: "https://app.bloody.example/incidents/42" });
    expect(JSON.stringify(card)).toContain("Acme MSSP");
  });

  it("validates Teams/Workflows webhook hosts", () => {
    const sender = new TeamsSender({ http: new FakeHttp(), secrets: new FakeSecrets({}) });
    expect(sender.validateConfig({ url: "https://contoso.webhook.office.com/webhookb2/abc" }).ok).toBe(true);
    expect(sender.validateConfig({ url: "https://prod-12.westeurope.logic.azure.com/workflows/x" }).ok).toBe(true);
    expect(sender.validateConfig({ url: "https://webhook.office.com.evil.io/x" }).ok).toBe(false);
  });
});

describe("syslog channel", () => {
  it("formats RFC 5424 with structured data escaping", () => {
    const line = formatRfc5424({
      facility: 13,
      severity: 2,
      timestamp: new Date("2026-10-07T11:58:00.000Z"),
      hostname: "bloody-api-1",
      appName: "bloody",
      procId: null,
      msgId: "incident.created",
      structuredData: [{ id: "bloody@32473", params: { org: 'Acme "Corp" [EU]\\', n: 1 } }],
      message: "line one\nline two",
    });
    expect(line).toBe('<106>1 2026-10-07T11:58:00.000Z bloody-api-1 bloody - incident.created [bloody@32473 org="Acme \\"Corp\\" [EU\\]\\\\" n="1"] ﻿line one line two');
    expect(escapeSdValue('a"b]c\\')).toBe('a\\"b\\]c\\\\');
    const msg = buildSyslogMessage(message, { facility: 16, appName: "bloody", enterpriseId: "32473" }, "host");
    expect(msg.startsWith("<130>1 2026-10-07T11:58:00.000Z host bloody - incident.created [bloody@32473 tenant=")).toBe(true);
    expect(msg).toContain('f_risk_score="91"');
  });

  it("sends via the injected transport, truncating UDP datagrams at UTF-8 boundaries", async () => {
    const transport = new RecordingSyslogTransport();
    const sender = new SyslogSender({ transport, secrets: new FakeSecrets({}), hostname: "bloody", maxUdpBytes: 200 });
    const res = await sender.send(channel("syslog", { host: "siem.example.com", protocol: "udp" }), { ...message, text: "é".repeat(500) });
    expect(res.warnings?.[0]).toMatch(/truncated/);
    expect(transport.sent[0]!.target).toEqual({ host: "siem.example.com", port: 514, protocol: "udp" });
    expect(transport.sent[0]!.payload.length).toBeLessThanOrEqual(200);
    expect(() => transport.sent[0]!.payload.toString("utf8")).not.toThrow();
    expect(truncateUtf8(Buffer.from("aé", "utf8"), 2).toString("utf8")).toBe("a");
    await sender.send(channel("syslog", { host: "siem.example.com" }), message);
    expect(transport.sent[1]!.target).toEqual({ host: "siem.example.com", port: 6514, protocol: "tls" });
    expect(sender.validateConfig({ host: "169.254.169.254" }).ok).toBe(false);
    expect(sender.validateConfig({ host: "10.0.0.10", protocol: "tcp", port: 1514 }).ok).toBe(true);
  });
});

describe("e-mail channel", () => {
  const logo = `data:image/png;base64,${Buffer.from("89504e470d0a1a0a0000000d49484452", "hex").toString("base64")}`;

  it("composes a branded HTML + text e-mail with safe headers and threading", () => {
    const mail = composeEmail(message, {
      from: { address: "notifications@soc.example.com" },
      brand: resolveBranding({ name: "Acme MSSP", primaryColor: "#0055AA", logoDataUrl: logo, supportEmail: "soc@acme-mssp.example" }),
      config: { to: ["ciso@customer.example"], cc: [], bcc: [], subjectPrefix: "[SOC]" },
      appBaseUrl: "https://app.bloody.example",
    });
    expect(mail.subject).toBe("[SOC] [CRITICAL] Incident #42: Ransomware on <FIN-WS-042>");
    const html = String(mail.html);
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;FIN-WS-042&gt;");
    expect(html).toContain('src="cid:brand-logo@bloody"');
    expect(html).toContain("#0055AA");
    expect(html).toContain("Acme &lt;Corp&gt;");
    expect(html).toContain('href="https://app.bloody.example/incidents/42"');
    expect(html).toContain("Critical incidents to SOC");
    expect(String(mail.text)).toContain("Risk score  91");
    expect(String(mail.text)).toContain("Open incident: https://app.bloody.example/incidents/42");
    expect(mail.priority).toBe("high");
    expect(mail.headers).toMatchObject({ "Auto-Submitted": "auto-generated", "X-Bloody-Event": "incident.created", "List-Unsubscribe": "<https://app.bloody.example/settings/notifications>" });
    expect(mail.references).toEqual([mail.inReplyTo]);
    expect(String(mail.inReplyTo)).toMatch(/^<thread-[0-9a-f]{24}@soc\.example\.com>$/);
    expect(mail.replyTo).toBe("soc@acme-mssp.example");
  });

  it("sends through nodemailer (stream transport) producing a valid MIME message", async () => {
    const transport = nodemailer.createTransport({ streamTransport: true, buffer: true, newline: "unix" });
    const sender = new EmailSender({
      transport,
      from: { address: "notifications@soc.example.com", name: "Bloody SOC" },
      branding: async () => resolveBranding({ name: "Acme MSSP", primaryColor: "#0055AA", logoDataUrl: logo }),
      clock: new FakeClock(),
      ids: sequentialIds(),
    });
    const ch = channel("email", { to: ["CISO@Customer.example"], bcc: ["audit@acme-mssp.example"] }, { organizationId: ORG_A });
    const attachment = { filename: "executive-report.pdf", contentType: "application/pdf", content: Buffer.from("%PDF-1.7 test") };
    const res = await sender.send(ch, { ...message, subject: "Bad\r\nBcc: attacker@evil.example", attachments: [attachment] });
    expect(res.ok).toBe(true);
    const raw = ((await transport.sendMail(await sender.compose(ch, { ...message, attachments: [attachment] }))) as unknown as { message: Buffer }).message.toString("utf8");
    expect(raw).toMatch(/^From: Acme MSSP Security Operations <notifications@soc\.example\.com>$/m);
    expect(raw).toMatch(/^To: ciso@customer\.example$/m);
    expect(raw).toContain("Content-Type: multipart/mixed");
    expect(raw).toContain("Content-Type: text/plain");
    expect(raw).toContain("Content-Type: text/html");
    expect(raw).toContain("Content-Type: application/pdf; name=executive-report.pdf");
    expect(raw).toContain("Content-ID: <brand-logo@bloody>");
    expect(raw).toMatch(/^Auto-Submitted: auto-generated$/m);
    const injected = ((await transport.sendMail(await sender.compose(ch, { ...message, subject: "Bad\r\nBcc: attacker@evil.example" }))) as unknown as { message: Buffer }).message.toString("utf8");
    expect(injected).toMatch(/^Subject: Bad Bcc: attacker@evil\.example$/m);
    expect(injected).not.toMatch(/^Bcc: attacker/m);
  });

  it("validates recipients and maps SMTP errors", async () => {
    const sender = new EmailSender({ transport: nodemailer.createTransport({ jsonTransport: true }), from: { address: "n@soc.example.com" } });
    expect(sender.validateConfig({ to: [] }).ok).toBe(false);
    expect(sender.validateConfig({ to: ["not-an-email"] }).ok).toBe(false);
    expect(sender.validateConfig({ to: ["a@b.example"], subjectPrefix: "x\r\nBcc: y" }).ok).toBe(false);
    const failing = new EmailSender({
      transport: { sendMail: async () => Promise.reject(Object.assign(new Error("mailbox unavailable"), { responseCode: 550, code: "EENVELOPE" })) } as unknown as ReturnType<typeof nodemailer.createTransport>,
      from: { address: "n@soc.example.com" },
    });
    await expect(failing.send(channel("email", { to: ["a@b.example"] }), message)).rejects.toMatchObject({ retryable: false, code: "smtp_eenvelope" });
    const transient = new EmailSender({
      transport: { sendMail: async () => Promise.reject(Object.assign(new Error("try later"), { responseCode: 421 })) } as unknown as ReturnType<typeof nodemailer.createTransport>,
      from: { address: "n@soc.example.com" },
    });
    await expect(transient.send(channel("email", { to: ["a@b.example"] }), message)).rejects.toBeInstanceOf(DeliveryError);
    await expect(transient.send(channel("email", { to: ["a@b.example"] }), message)).rejects.toMatchObject({ retryable: true });
  });

  it("sends test messages via the registry (json transport)", async () => {
    const transport = nodemailer.createTransport({ jsonTransport: true });
    const registry = new ChannelRegistry([new EmailSender({ transport, from: { address: "n@soc.example.com" }, clock: new FakeClock(), ids: sequentialIds() })]);
    const res = await registry.test(channel("email", { to: ["soc@customer.example"] }, { enabled: false }), { requestedBy: "alice" });
    expect(res.kind).toBe("email");
    expect(registry.validate("slack", {}).ok).toBe(false);
  });
});

describe("in-app channel", () => {
  it("stores notifications with safe links", async () => {
    const store = new InMemoryInAppStore();
    const sender = new InAppSender({ store, clock: new FakeClock() });
    await sender.send(channel("in_app", { roles: ["soc_analyst_t1"] }), { ...message, link: { url: "javascript:alert(1)", label: "x" } });
    await sender.send(channel("in_app", {}), { ...message, link: { url: "/incidents/42", label: "Open" } });
    expect(store.items[0]!.link).toBeNull();
    expect(store.items[0]!.recipients.roles).toEqual(["soc_analyst_t1"]);
    expect(store.items[1]!.link).toEqual({ url: "/incidents/42", label: "Open" });
    expect(sender.validateConfig({ roles: ["not_a_role"] }).ok).toBe(false);
  });
});

describe("branding", () => {
  it("falls back field-by-field to the default brand", () => {
    const b = resolveBranding({ name: "Acme MSSP", primaryColor: "red", logoDataUrl: "data:text/html;base64,PHNjcmlwdD4=" });
    expect(b.name).toBe("Acme MSSP");
    expect(b.primaryColor).toBe(DEFAULT_BRANDING.primaryColor);
    expect(b.logoDataUrl).toBeNull();
  });
});
