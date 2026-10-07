import { describe, expect, it } from "vitest";
import { SsrfBlockedError } from "../errors.js";
import { createProvider } from "../providers/factory.js";
import { fakeFetch } from "../test-support/fake-fetch.js";
import { providerConfig } from "../test-support/fixtures.js";
import { classifyIp, parseIPv6 } from "./ip.js";
import { assertSafeEndpoint, assertSafeEndpointResolved, checkEndpoint } from "./ssrf.js";

const reason = (url: string, allowPrivate = false, requireHttps = false): string | null => {
  const r = checkEndpoint(url, { allowPrivate, requireHttps });
  return r.ok ? null : r.reason;
};

describe("SSRF guard", () => {
  it("always blocks cloud metadata endpoints, even with allowPrivate", () => {
    for (const url of [
      "http://169.254.169.254/latest/meta-data/",
      "http://[fd00:ec2::254]/",
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://metadata.google.internal./",
      "http://2852039166/", // decimal 169.254.169.254
      "http://0xa9fea9fe/", // hex
      "http://[::ffff:169.254.169.254]/", // IPv4-mapped
      "http://169.254.170.2/v2/credentials",
      "http://100.100.100.200/",
    ]) {
      expect(reason(url, true), url).toBe("metadata_endpoint");
    }
  });

  it("blocks link-local, unspecified and reserved ranges always", () => {
    expect(reason("http://169.254.10.1/", true)).toBe("link_local");
    expect(reason("http://[fe80::1]/", true)).toBe("link_local");
    expect(reason("http://0.0.0.0:11434/", true)).toBe("reserved_address");
    expect(reason("http://[::]/", true)).toBe("reserved_address");
    expect(reason("http://240.0.0.1/", true)).toBe("reserved_address");
    expect(reason("http://224.0.0.1/", true)).toBe("reserved_address");
  });

  it("allows loopback/private endpoints only when the tenant allows private endpoints", () => {
    expect(reason("http://localhost:11434")).toBe("loopback");
    expect(reason("http://127.0.0.1:1234/v1")).toBe("loopback");
    expect(reason("http://[::1]:8000/v1")).toBe("loopback");
    expect(reason("http://10.0.0.5:8000/v1")).toBe("private_address");
    expect(reason("http://192.168.1.20/")).toBe("private_address");
    expect(reason("http://100.64.1.1/")).toBe("private_address");
    expect(reason("http://[fd12:3456::1]/")).toBe("private_address");
    expect(reason("http://ollama:11434")).toBe("private_hostname");
    expect(reason("http://llm.corp.internal/")).toBe("private_hostname");
    for (const url of ["http://localhost:11434", "http://10.0.0.5:8000/v1", "http://ollama:11434", "http://[fd12:3456::1]/"]) expect(reason(url, true), url).toBeNull();
  });

  it("validates scheme, credentials and https requirements", () => {
    expect(reason("file:///etc/passwd")).toBe("unsupported_scheme");
    expect(reason("gopher://example.com/")).toBe("unsupported_scheme");
    expect(reason("https://user:pass@api.example.com/")).toBe("credentials_in_url");
    expect(reason("not a url")).toBe("invalid_url");
    expect(reason("http://api.openai.com/v1", false, true)).toBe("https_required");
    expect(reason("https://api.openai.com/v1", false, true)).toBeNull();
  });

  it("classifies embedded IPv4 in IPv6 transition prefixes", () => {
    expect(classifyIp("64:ff9b::a9fe:a9fe")).toBe("metadata");
    expect(classifyIp("2002:a9fe:a9fe::1")).toBe("metadata");
    expect(classifyIp("::ffff:10.0.0.1")).toBe("private");
    expect(classifyIp("2606:4700::1111")).toBe("public");
    expect(parseIPv6("1:2:3:4:5:6:7:8:9")).toBeNull();
  });

  it("rejects hostnames that resolve to internal or metadata addresses", async () => {
    const resolver = async (h: string): Promise<string[]> => (h === "evil.example.com" ? ["93.184.216.34", "169.254.169.254"] : h === "intranet.example.com" ? ["10.2.3.4"] : ["93.184.216.34"]);
    await expect(assertSafeEndpointResolved("https://evil.example.com/v1", { allowPrivate: true }, resolver)).rejects.toMatchObject({ reason: "metadata_endpoint" });
    await expect(assertSafeEndpointResolved("https://intranet.example.com/v1", { allowPrivate: false }, resolver)).rejects.toMatchObject({ reason: "private_address" });
    await expect(assertSafeEndpointResolved("https://intranet.example.com/v1", { allowPrivate: true }, resolver)).resolves.toBeInstanceOf(URL);
    await expect(assertSafeEndpointResolved("https://ok.example.com/v1", { allowPrivate: false }, resolver)).resolves.toBeInstanceOf(URL);
    await expect(assertSafeEndpointResolved("https://nx.example.com/", { allowPrivate: false }, async () => Promise.reject(new Error("ENOTFOUND")))).rejects.toMatchObject({ reason: "unresolvable" });
  });

  it("is enforced when creating providers", () => {
    const { fetch } = fakeFetch([]);
    expect(() => createProvider(providerConfig({ kind: "ollama", endpoint: null, credentialRef: null }), null, fetch)).toThrow(SsrfBlockedError);
    expect(() => createProvider(providerConfig({ kind: "ollama", endpoint: null, credentialRef: null }), null, fetch, { allowPrivateEndpoints: true })).not.toThrow();
    expect(() => createProvider(providerConfig({ kind: "vllm", endpoint: "http://169.254.169.254/v1" }), null, fetch, { allowPrivateEndpoints: true })).toThrow(SsrfBlockedError);
    expect(() => createProvider(providerConfig({ kind: "openai", endpoint: "http://api.openai.com/v1" }), "sk-test", fetch)).toThrow(/https/);
    expect(() => assertSafeEndpoint("https://api.anthropic.com", { allowPrivate: false, requireHttps: true })).not.toThrow();
  });
});
