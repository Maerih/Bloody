import { describe, expect, it } from "vitest";
import {
  defang,
  escapeHtml,
  renderParameters,
  renderTemplate,
  renderTemplateDetailed,
  sanitizeHeaderValue,
  templateVariables,
  textToHtml,
  validateTemplate,
} from "./template.js";

const ctx = {
  severity: "critical",
  incident: { number: 42, title: `<img src=x onerror="alert(1)">`, riskScore: 0.913, detectedAt: "2026-10-07T10:05:00Z", techniques: ["T1059", "T1486"], assignee: null },
  indicator: { value: "https://evil.example.com/payload", type: "url" },
  organization: { name: "Acme & Sons" },
};

describe("template rendering", () => {
  it("interpolates dotted paths and applies filters", () => {
    expect(renderTemplate("[{{ severity | upper }}] #{{incident.number}}", ctx)).toBe("[CRITICAL] #42");
    expect(renderTemplate("{{incident.techniques | join:\" / \"}}", ctx)).toBe("T1059 / T1486");
    expect(renderTemplate("{{incident.assignee | default:\"unassigned\"}}", ctx)).toBe("unassigned");
    expect(renderTemplate("{{incident.riskScore | percent}}", ctx)).toBe("91.3%");
    expect(renderTemplate("{{incident.detectedAt | datetime}}", ctx)).toBe("07 Oct 2026 10:05 UTC");
    expect(renderTemplate("{{incident.title | truncate:5}}", { incident: { title: "abcdefghij" } })).toBe("abcd…");
    expect(renderTemplate("{{indicator.value | defang}}", ctx)).toBe("hxxps://evil[.]example[.]com/payload");
    expect(renderTemplate("{{n | number}}", { n: 1234567.891 })).toBe("1,234,567.891");
  });

  it("HTML-escapes every interpolated value in html mode", () => {
    const out = renderTemplate("<p>{{incident.title}} for {{organization.name}}</p>", ctx, { escape: "html" });
    expect(out).toBe("<p>&lt;img src&#61;x onerror&#61;&quot;alert(1)&quot;&gt; for Acme &amp; Sons</p>");
    expect(out).not.toContain("<img");
  });

  it("has no code execution or prototype access", () => {
    expect(renderTemplate("{{constructor.constructor}}", ctx)).toBe("");
    expect(renderTemplate("{{incident.__proto__}}", ctx)).toBe("");
    expect(renderTemplate("{{ process.env.HOME }}", ctx)).toBe("");
    expect(renderTemplate("{{ 1 + 1 }}", ctx)).toBe("");
    const r = renderTemplateDetailed("{{ incident.title | exec:\"rm -rf\" }}", { incident: { title: "x" } });
    expect(r.output).toBe("x");
    expect(r.warnings[0]).toMatch(/unknown filter "exec"/);
  });

  it("reports missing variables and validates templates", () => {
    const r = renderTemplateDetailed("Hi {{user.name}} {{severity}}", ctx);
    expect(r.missing).toEqual(["user.name"]);
    expect(templateVariables("{{a.b}} {{ c | upper }} {{a.b}}")).toEqual(["a.b", "c"]);
    expect(validateTemplate("{{a | nosuch}}")[0]!.message).toMatch(/unknown filter/);
    expect(validateTemplate("{{ unclosed")[0]!.message).toMatch(/unbalanced/);
    expect(validateTemplate("{{x.y}}", { knownRoots: ["incident"] })[0]!.message).toMatch(/unknown variable/);
    expect(validateTemplate("{{incident.title | upper}}")).toEqual([]);
  });

  it("sanitizes header values against CR/LF injection", () => {
    expect(sanitizeHeaderValue("Alert\r\nBcc: victim@example.com")).toBe("Alert Bcc: victim@example.com");
    expect(sanitizeHeaderValue("a".repeat(300), 10)).toHaveLength(10);
  });

  it("converts text to safe HTML with paragraphs, bullets, bold and links", () => {
    const html = textToHtml("Hello **team** <script>x</script>\n\n- one\n- see https://app.example.com/i/1?a=1&b=2\n\nbye");
    expect(html).toContain("<strong>team</strong>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain("<ul");
    expect(html).toContain('href="https://app.example.com/i/1?a&#61;1&amp;b&#61;2"');
    expect(html.match(/<p /g)).toHaveLength(2);
    expect(escapeHtml(`"'\`=`)).toBe("&quot;&#39;&#96;&#61;");
    expect(defang("10.0.0.1")).toBe("10[.]0[.]0[.]1");
  });

  it("renders step parameters keeping raw types for single-tag strings", () => {
    const p = renderParameters({ ip: "{{indicator.value}}", note: "Incident {{incident.number}}", n: 3, nested: { list: ["{{incident.number}}"] } }, ctx);
    expect(p).toEqual({ ip: "https://evil.example.com/payload", note: "Incident 42", n: 3, nested: { list: [42] } });
  });
});
