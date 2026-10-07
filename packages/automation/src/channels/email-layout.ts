import type { Severity } from "@bloody/contracts";
import { escapeHtml, stripControlChars, textToHtml } from "../template.js";
import { eventLabel, SEVERITY_COLORS, SEVERITY_LABEL, type Branding, type NotificationFact } from "./types.js";

/**
 * Branded, responsive HTML e-mail layout used for every Bloody e-mail (alerts, approvals,
 * digests, scheduled reports). Table-based with inline styles so it renders in Outlook, Gmail,
 * Apple Mail and mobile clients; a small <style> block adds the mobile breakpoint and dark-mode
 * refinements for clients that support them. All dynamic text is escaped.
 */
export interface EmailLayoutInput {
  brand: Branding;
  /** cid: or https: URL of the logo image (data: URLs are blocked by most webmail). */
  logoSrc?: string | null;
  severity: Severity;
  event: string;
  title: string;
  /** Inbox preview line (hidden in the body). */
  preheader: string;
  /** Already-safe HTML body (use {@link textToHtml} for text). */
  bodyHtml: string;
  facts: NotificationFact[];
  cta?: { url: string; label: string } | null;
  organizationName?: string | null;
  occurredAt: string;
  /** "You are receiving this because …" */
  reason?: string | null;
  manageUrl?: string | null;
  /** Optional attachment list rendered as a "Files" panel (scheduled reports). */
  attachments?: { filename: string; sizeBytes: number }[];
}

const INK = "#0B0B0B";
const INK_2 = "#52514E";
const MUTED = "#898781";
const HAIRLINE = "#E1E0D9";
const PAGE = "#F4F4F1";
const CARD = "#FFFFFF";
const HEADER = "#14181F";

/** Pick white or near-black text for a background colour (WCAG relative luminance). */
export function contrastText(hex: string): string {
  const m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
  if (!m) return "#FFFFFF";
  const lin = (c: string): number => {
    const v = parseInt(c, 16) / 255;
    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  };
  const l = 0.2126 * lin(m[1]!) + 0.7152 * lin(m[2]!) + 0.0722 * lin(m[3]!);
  return (1.05) / (l + 0.05) >= (l + 0.05) / 0.05 ? "#FFFFFF" : INK;
}

function safeHttpsUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.protocol === "https:" ? u.toString() : null;
  } catch {
    return null;
  }
}

function formatWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 16)} UTC`;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function renderEmailHtml(input: EmailLayoutInput): string {
  const brand = input.brand;
  const primary = /^#[0-9a-f]{6}$/i.test(brand.primaryColor) ? brand.primaryColor : "#B4232C";
  const onPrimary = contrastText(primary);
  const sevColor = SEVERITY_COLORS[input.severity];
  const sevLabel = SEVERITY_LABEL[input.severity];
  const cta = input.cta ? safeHttpsUrl(input.cta.url) : null;
  const manage = safeHttpsUrl(input.manageUrl ?? null);
  const website = safeHttpsUrl(brand.website ?? null);
  const title = escapeHtml(stripControlChars(input.title));
  const logoSrc = input.logoSrc && (input.logoSrc.startsWith("cid:") || safeHttpsUrl(input.logoSrc)) ? input.logoSrc : null;
  const brandMark = logoSrc
    ? `<img src="${escapeHtml(logoSrc)}" alt="${escapeHtml(brand.name)}" height="28" style="display:block;height:28px;max-width:180px;border:0;outline:none;text-decoration:none;">`
    : `<span style="font-size:18px;font-weight:700;letter-spacing:.2px;color:#FFFFFF;">${escapeHtml(brand.name)}</span>`;

  const factsRows = input.facts
    .slice(0, 20)
    .map(
      (f, i) =>
        `<tr><td class="fact-label" style="padding:9px 12px;font-size:13px;color:${INK_2};width:38%;vertical-align:top;border-top:${i === 0 ? "0" : `1px solid ${HAIRLINE}`};">${escapeHtml(stripControlChars(f.label))}</td><td class="fact-value" style="padding:9px 12px;font-size:13px;color:${INK};font-weight:600;vertical-align:top;word-break:break-word;border-top:${i === 0 ? "0" : `1px solid ${HAIRLINE}`};">${escapeHtml(stripControlChars(f.value))}</td></tr>`,
    )
    .join("");
  const factsBlock = factsRows
    ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="facts" style="border:1px solid ${HAIRLINE};border-radius:8px;border-collapse:separate;margin:8px 0 24px 0;background:#FAFAF8;">${factsRows}</table>`
    : "";

  const filesBlock =
    input.attachments && input.attachments.length > 0
      ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 24px 0;">${input.attachments
          .map(
            (a) =>
              `<tr><td style="padding:10px 12px;border:1px solid ${HAIRLINE};border-radius:8px;font-size:13px;color:${INK};"><span style="display:inline-block;padding:2px 6px;margin-right:8px;border-radius:4px;background:${primary};color:${onPrimary};font-size:11px;font-weight:700;">${escapeHtml((a.filename.split(".").pop() ?? "file").toUpperCase())}</span>${escapeHtml(a.filename)} <span style="color:${MUTED};">· ${formatBytes(a.sizeBytes)}</span></td></tr>`,
          )
          .join("")}</table>`
      : "";

  const ctaBlock = cta
    ? `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:4px 0 8px 0;"><tr><td align="center" bgcolor="${primary}" style="border-radius:6px;background:${primary};"><a href="${escapeHtml(cta)}" target="_blank" rel="noopener noreferrer" class="cta" style="display:inline-block;padding:12px 22px;font-size:14px;font-weight:600;color:${onPrimary};text-decoration:none;border-radius:6px;">${escapeHtml(stripControlChars(input.cta!.label))} &rarr;</a></td></tr></table>`
    : "";

  const footerLines = [
    `Sent by ${escapeHtml(brand.name)} Security Operations${input.organizationName ? ` for ${escapeHtml(input.organizationName)}` : ""}.`,
    input.reason ? escapeHtml(stripControlChars(input.reason)) : null,
    brand.footerText ? escapeHtml(stripControlChars(brand.footerText)) : null,
    [manage ? `<a href="${escapeHtml(manage)}" style="color:${INK_2};text-decoration:underline;">Manage notifications</a>` : null, website ? `<a href="${escapeHtml(website)}" style="color:${INK_2};text-decoration:underline;">${escapeHtml(new URL(website).hostname)}</a>` : null, brand.supportEmail ? `<a href="mailto:${escapeHtml(brand.supportEmail)}" style="color:${INK_2};text-decoration:underline;">${escapeHtml(brand.supportEmail)}</a>` : null]
      .filter(Boolean)
      .join(" &nbsp;·&nbsp; ") || null,
    "This message was generated automatically. Do not reply with sensitive information.",
  ]
    .filter(Boolean)
    .map((l) => `<p style="margin:0 0 6px 0;">${l}</p>`)
    .join("");

  const eyebrow = `${escapeHtml(eventLabel(input.event).toUpperCase())}${input.organizationName ? ` &nbsp;·&nbsp; ${escapeHtml(input.organizationName.toUpperCase())}` : ""}`;

  return `<!doctype html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<meta name="format-detection" content="telephone=no, date=no, address=no, email=no">
<title>${title}</title>
<style>
  body,table,td,a{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;}
  table,td{mso-table-lspace:0pt;mso-table-rspace:0pt;}
  img{-ms-interpolation-mode:bicubic;}
  a{color:${primary};}
  @media only screen and (max-width:620px){
    .container{width:100% !important;}
    .px{padding-left:20px !important;padding-right:20px !important;}
    .h1{font-size:20px !important;line-height:28px !important;}
    .fact-label,.fact-value{display:block !important;width:auto !important;}
    .fact-value{padding-top:0 !important;border-top:0 !important;}
    .cta{display:block !important;}
  }
  @media (prefers-color-scheme: dark){
    .page{background:#0D0D0D !important;}
    .card{background:#1A1A19 !important;}
    .ink{color:#FFFFFF !important;}
    .ink2{color:#C3C2B7 !important;}
    .facts{background:#222220 !important;border-color:#2C2C2A !important;}
    .fact-value{color:#FFFFFF !important;}
    .fact-label{color:#C3C2B7 !important;}
  }
</style>
</head>
<body class="page" style="margin:0;padding:0;background:${PAGE};font-family:system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;mso-hide:all;font-size:1px;line-height:1px;color:${PAGE};">${escapeHtml(stripControlChars(input.preheader)).slice(0, 200)}&#8203;&#160;&#8203;&#160;&#8203;&#160;&#8203;&#160;</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="page" style="background:${PAGE};">
<tr><td align="center" style="padding:24px 12px;">
  <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" class="container" style="width:600px;max-width:600px;">
    <tr><td class="px" style="background:${HEADER};padding:16px 28px;border-radius:10px 10px 0 0;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
        <td align="left" style="vertical-align:middle;">${brandMark}</td>
        <td align="right" style="vertical-align:middle;"><span style="display:inline-block;padding:4px 10px;border-radius:999px;background:${sevColor};color:#FFFFFF;font-size:11px;font-weight:700;letter-spacing:.6px;">${escapeHtml(sevLabel.toUpperCase())}</span></td>
      </tr></table>
    </td></tr>
    <tr><td style="height:4px;line-height:4px;font-size:4px;background:${sevColor};">&nbsp;</td></tr>
    <tr><td class="card px" style="background:${CARD};padding:28px 28px 8px 28px;">
      <p class="ink2" style="margin:0 0 8px 0;font-size:11px;font-weight:700;letter-spacing:.8px;color:${MUTED};">${eyebrow}</p>
      <h1 class="h1 ink" style="margin:0 0 6px 0;font-size:22px;line-height:30px;font-weight:700;color:${INK};">${title}</h1>
      <p class="ink2" style="margin:0 0 20px 0;font-size:12px;color:${MUTED};">${escapeHtml(formatWhen(input.occurredAt))}</p>
      <div class="ink" style="font-size:15px;line-height:23px;color:${INK};">${input.bodyHtml}</div>
      ${factsBlock}
      ${filesBlock}
      ${ctaBlock}
    </td></tr>
    <tr><td class="card px" style="background:${CARD};padding:8px 28px 24px 28px;border-radius:0 0 10px 10px;">&nbsp;</td></tr>
    <tr><td class="px ink2" style="padding:18px 28px 0 28px;font-size:12px;line-height:18px;color:${MUTED};">${footerLines}</td></tr>
  </table>
</td></tr>
</table>
</body>
</html>`;
}

/** Plain-text alternative mirroring the HTML structure. */
export function renderEmailText(input: Omit<EmailLayoutInput, "bodyHtml" | "logoSrc"> & { bodyText: string }): string {
  const lines: string[] = [];
  lines.push(`${input.brand.name} · ${eventLabel(input.event)} · ${SEVERITY_LABEL[input.severity]}`);
  if (input.organizationName) lines.push(input.organizationName);
  lines.push("", stripControlChars(input.title), "=".repeat(Math.min(72, Math.max(8, input.title.length))), formatWhen(input.occurredAt), "");
  lines.push(stripControlChars(input.bodyText).replace(/\*\*([^*]+?)\*\*/g, "$1"), "");
  if (input.facts.length > 0) {
    const width = Math.min(28, Math.max(...input.facts.map((f) => f.label.length)));
    for (const f of input.facts.slice(0, 20)) lines.push(`${stripControlChars(f.label).padEnd(width)}  ${stripControlChars(f.value)}`);
    lines.push("");
  }
  if (input.attachments?.length) {
    lines.push("Attached:");
    for (const a of input.attachments) lines.push(`  - ${a.filename} (${formatBytes(a.sizeBytes)})`);
    lines.push("");
  }
  const cta = input.cta ? safeHttpsUrl(input.cta.url) : null;
  if (cta) lines.push(`${input.cta!.label}: ${cta}`, "");
  lines.push("--", `Sent by ${input.brand.name} Security Operations${input.organizationName ? ` for ${input.organizationName}` : ""}.`);
  if (input.reason) lines.push(input.reason);
  if (input.brand.footerText) lines.push(input.brand.footerText);
  const manage = safeHttpsUrl(input.manageUrl ?? null);
  if (manage) lines.push(`Manage notifications: ${manage}`);
  return lines.join("\n");
}

export { textToHtml };
