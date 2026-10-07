import { describe, expect, it } from "vitest";
import { AiPolicyError } from "../errors.js";
import { createProvider } from "../providers/factory.js";
import { fakeFetch } from "../test-support/fake-fetch.js";
import { providerConfig } from "../test-support/fixtures.js";
import { assertTenantDataAllowed, classifyEgress } from "./egress.js";
import { RedactionVault, Redactor, StreamingRehydrator, emptyRedactionStats, scrubSecrets } from "./redact.js";

describe("Redactor", () => {
  const vault = new RedactionVault(Buffer.alloc(32, 7));
  const secrets = new Redactor({ secrets: true, pii: false });

  it("redacts common credential formats", () => {
    const samples: Array<[string, string]> = [
      ["key AKIAIOSFODNN7EXAMPLE used", "aws_access_key"],
      ["aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_secret_key"],
      ["token ghp_0123456789abcdefghijklmnopqrstuvwxyzAB", "github_token"],
      ["sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123", "anthropic_key"],
      ["OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345", "openai_key"],
      ["xoxb-123456789012-abcdefghijkl", "slack_token"],
      ["https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXX", "slack_webhook"],
      ["Authorization: Bearer abcdefghijklmnopqrstuvwxyz.0123", "bearer_token"],
      ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "jwt"],
      ["postgres://app:S3cr3tPassw0rd@db.internal:5432/app", "url_credentials"],
      ["DefaultEndpointsProtocol=https;AccountName=x;AccountKey=abcdefGHIJKL0123456789==;", "connection_secret"],
      ['{"password": "hunter2hunter2"}', "password"],
      ["net use \\\\srv /user:admin --password Winter2026!", "password"],
      ["AIzaSyA1234567890abcdefghijklmnopqrstuv", "google_api_key"],
      ["bk_live_abcdefghijklmnopqrstuv", "bloody_api_key"],
    ];
    for (const [text, kind] of samples) {
      const stats = emptyRedactionStats();
      const out = secrets.redactText(text, vault, stats);
      expect(out, text).toContain(`[REDACTED:${kind}:`);
      expect(stats.byKind[kind as keyof typeof stats.byKind], text).toBeGreaterThan(0);
    }
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
    expect(secrets.redactText(`key:\n${pem}\nend`, vault)).toMatch(/^key:\n\[REDACTED:private_key:[0-9a-f]{8}\]\nend$/);
  });

  it("keeps surrounding context and is stable within a vault", () => {
    const a = secrets.redactText("password=Winter2026! on host fin-ws-01", vault);
    const b = secrets.redactText("again password=Winter2026!", vault);
    const ph = /\[REDACTED:password:[0-9a-f]{8}\]/.exec(a)![0];
    expect(a).toBe(`password=${ph} on host fin-ws-01`);
    expect(b).toContain(ph);
    expect(vault.rehydrate(`the value ${ph}`)).toBe("the value Winter2026!");
    const other = new RedactionVault();
    expect(secrets.redactText("password=Winter2026!", other)).not.toContain(ph);
  });

  it("does not re-redact placeholders and leaves ordinary text alone", () => {
    const once = secrets.redactText("api_key=abcd1234efgh", vault);
    expect(secrets.redactText(once, vault)).toBe(once);
    expect(secrets.redactText("PWD=/home/analyst and 10.1.2.3 connected to 8.8.8.8", vault)).toBe("PWD=/home/analyst and 10.1.2.3 connected to 8.8.8.8");
  });

  it("redacts PII only when enabled (cards validated by Luhn)", () => {
    const text = "Contact jane.doe@corp.example, card 4111 1111 1111 1111, not-a-card 1234 5678 9012 3456, ssn 123-45-6789, iban GB82 WEST 1234 5698 7654 32";
    expect(secrets.redactText(text, vault)).toBe(text);
    const pii = new Redactor({ secrets: true, pii: true });
    const out = pii.redactText(text, vault);
    expect(out).toContain("[REDACTED:email:");
    expect(out).toContain("[REDACTED:credit_card:");
    expect(out).toContain("1234 5678 9012 3456");
    expect(out).toContain("[REDACTED:us_ssn:");
    expect(out).toContain("[REDACTED:iban:");
  });

  it("deep-redacts values under sensitive keys", () => {
    const out = secrets.redactValue({ user: "svc", password: "x1", nested: { apiKey: 12345, note: "token sk-proj-abcdefghijklmnopqrstuvwxyz0" }, list: [{ secret: "s" }] }, vault);
    expect(out.user).toBe("svc");
    expect(out.password).toMatch(/^\[REDACTED:secret_value:/);
    expect(String(out.nested.apiKey)).toMatch(/^\[REDACTED:secret_value:/);
    expect(out.nested.note).toContain("[REDACTED:openai_key:");
    expect(out.list[0]!.secret).toMatch(/^\[REDACTED:secret_value:/);
  });

  it("re-hydrates placeholders split across streamed chunks", () => {
    const v = new RedactionVault();
    const ph = v.placeholder("password", "Winter2026!");
    const out: string[] = [];
    const r = new StreamingRehydrator(v, (t) => out.push(t));
    const text = `The password ${ph} was reused [sic].`;
    for (let i = 0; i < text.length; i += 5) r.push(text.slice(i, i + 5));
    r.flush();
    expect(out.join("")).toBe("The password Winter2026! was reused [sic].");
  });

  it("scrubSecrets is safe for log lines", () => {
    expect(scrubSecrets("x-api-key: sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaa")).not.toContain("aaaaaaaa");
  });
});

describe("Data egress governance", () => {
  it("classifies local kinds pointed at AI SaaS hosts as cloud", () => {
    expect(classifyEgress("ollama", "http://localhost:11434")).toBe("local");
    expect(classifyEgress("openai_compatible", "https://api.groq.com/openai/v1")).toBe("cloud");
    expect(classifyEgress("vllm", "https://llm.corp.example/v1")).toBe("local");
    expect(classifyEgress("anthropic", null)).toBe("cloud");
  });

  it("refuses tenant data for cloud providers when allowCloudData=false", () => {
    expect(() => assertTenantDataAllowed(providerConfig({ kind: "anthropic", allowCloudData: false }))).toThrow(AiPolicyError);
    expect(() => assertTenantDataAllowed(providerConfig({ kind: "openai_compatible", endpoint: "https://api.together.xyz/v1", allowCloudData: false }))).toThrow(/cloud/);
    expect(() => assertTenantDataAllowed(providerConfig({ kind: "ollama", endpoint: "http://10.0.0.2:11434", allowCloudData: false }))).not.toThrow();
    expect(() => assertTenantDataAllowed(providerConfig({ kind: "ollama", enabled: false }))).toThrow(/disabled/);
  });

  it("governed provider redacts outgoing content, re-hydrates tool arguments and blocks cloud egress", async () => {
    const config = providerConfig({ kind: "openai", redactSensitive: true, allowCloudData: true });
    const vault = new RedactionVault();
    const userText = "Investigate logons by jane.doe@corp.example with password=Winter2026!";
    // Model echoes the placeholder it saw back as a tool argument.
    const emailPh = vault.placeholder("email", "jane.doe@corp.example");
    const scripted = fakeFetch([
      {
        json: {
          choices: [{ finish_reason: "tool_calls", message: { content: `Searching ${emailPh}`, tool_calls: [{ id: "c1", type: "function", function: { name: "search_events", arguments: JSON.stringify({ query: `user.email:"${emailPh}"` }) } }] } }],
          usage: { prompt_tokens: 10, completion_tokens: 2 },
        },
      },
    ]);
    const governed = createProvider(config, "sk-test-key", scripted.fetch);
    const res = await governed.chat({ messages: [{ role: "user", content: userText }], redactionVault: vault });
    const sent = JSON.stringify(scripted.requests[0]!.body);
    expect(sent).not.toContain("Winter2026!");
    expect(sent).not.toContain("jane.doe@corp.example");
    expect(sent).toContain(emailPh);
    expect(res.message.toolCalls![0]!.arguments).toEqual({ query: 'user.email:"jane.doe@corp.example"' });
    expect(res.message.content).toBe("Searching jane.doe@corp.example");
    expect(res.redactions!.total).toBeGreaterThanOrEqual(2);

    const blocked = createProvider(providerConfig({ kind: "openai", allowCloudData: false }), "sk-test-key", scripted.fetch);
    await expect(blocked.chat({ messages: [{ role: "user", content: "hi" }] })).rejects.toBeInstanceOf(AiPolicyError);
    await expect(blocked.chat({ messages: [{ role: "user", content: "ping" }], dataClass: "public" })).resolves.toBeDefined();
  });

  it("local providers keep PII but still strip secrets", async () => {
    const { fetch, requests } = fakeFetch([{ json: { model: "llama3", message: { role: "assistant", content: "ok" }, done: true, prompt_eval_count: 5, eval_count: 1 } }]);
    const p = createProvider(providerConfig({ kind: "ollama", endpoint: "http://localhost:11434", credentialRef: null, allowCloudData: false }), null, fetch, { allowPrivateEndpoints: true });
    await p.chat({ messages: [{ role: "user", content: "user jane.doe@corp.example password=Winter2026!" }] });
    const sent = JSON.stringify(requests[0]!.body);
    expect(sent).toContain("jane.doe@corp.example");
    expect(sent).not.toContain("Winter2026!");
  });
});
