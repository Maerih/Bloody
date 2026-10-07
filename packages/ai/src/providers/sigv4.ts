import { createHash, createHmac } from "node:crypto";

/**
 * AWS Signature Version 4 (header-based), implemented from the AWS General Reference
 * specification with node:crypto. Used for Amazon Bedrock without the AWS SDK.
 */

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface SigV4Input {
  method: string;
  url: string;
  /** Headers that will be sent (Host is derived from the URL and must not be passed). */
  headers: Record<string, string>;
  body: string;
  region: string;
  service: string;
  credentials: AwsCredentials;
  now: Date;
  /** Non-S3 services URI-encode each path segment twice (default true). */
  doubleEncodePath?: boolean;
}

export interface SigV4Result {
  /** Headers to send: the input headers + x-amz-date (+ x-amz-security-token) + authorization. */
  headers: Record<string, string>;
  canonicalRequest: string;
  stringToSign: string;
  signedHeaders: string;
  credentialScope: string;
  signature: string;
}

const UNSIGNED_HEADERS = new Set(["authorization", "user-agent", "expect", "x-amzn-trace-id", "connection", "content-length"]);

export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function hmac(key: string | Buffer, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}

/** RFC 3986 strict encoding as required by SigV4 (encodes !'()* too). */
export function rfc3986Encode(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

export function formatAmzDate(date: Date): { amzDate: string; dateStamp: string } {
  const iso = date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  return { amzDate: iso, dateStamp: iso.slice(0, 8) };
}

export function deriveSigningKey(secretAccessKey: string, dateStamp: string, region: string, service: string): Buffer {
  const kDate = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, "aws4_request");
}

export function canonicalUri(pathname: string, doubleEncode: boolean): string {
  if (!pathname || pathname === "/") return "/";
  if (!doubleEncode) return pathname;
  return pathname
    .split("/")
    .map((segment) => rfc3986Encode(segment))
    .join("/");
}

export function canonicalQuery(search: URLSearchParams): string {
  const pairs: [string, string][] = [];
  search.forEach((value, key) => pairs.push([rfc3986Encode(key), rfc3986Encode(value)]));
  pairs.sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : a[0] < b[0] ? -1 : 1));
  return pairs.map(([k, v]) => `${k}=${v}`).join("&");
}

function canonicalHeaderValue(value: string): string {
  return value.trim().replace(/\s+/g, " ");
}

export function signSigV4(input: SigV4Input): SigV4Result {
  const url = new URL(input.url);
  const { amzDate, dateStamp } = formatAmzDate(input.now);
  const outHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(input.headers)) {
    const lk = k.toLowerCase();
    if (lk === "host" || lk === "authorization" || lk === "x-amz-date" || lk === "x-amz-security-token") continue;
    outHeaders[lk] = v;
  }
  outHeaders["x-amz-date"] = amzDate;
  if (input.credentials.sessionToken) outHeaders["x-amz-security-token"] = input.credentials.sessionToken;

  const toSign: Record<string, string> = { host: url.host };
  for (const [k, v] of Object.entries(outHeaders)) if (!UNSIGNED_HEADERS.has(k)) toSign[k] = canonicalHeaderValue(v);
  const names = Object.keys(toSign).sort();
  const canonicalHeaders = names.map((n) => `${n}:${toSign[n]}\n`).join("");
  const signedHeaders = names.join(";");

  const canonicalRequest = [
    input.method.toUpperCase(),
    canonicalUri(url.pathname, input.doubleEncodePath ?? true),
    canonicalQuery(url.searchParams),
    canonicalHeaders,
    signedHeaders,
    sha256Hex(input.body),
  ].join("\n");

  const credentialScope = `${dateStamp}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, credentialScope, sha256Hex(canonicalRequest)].join("\n");
  const signature = createHmac("sha256", deriveSigningKey(input.credentials.secretAccessKey, dateStamp, input.region, input.service))
    .update(stringToSign, "utf8")
    .digest("hex");

  outHeaders.authorization = `AWS4-HMAC-SHA256 Credential=${input.credentials.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { headers: outHeaders, canonicalRequest, stringToSign, signedHeaders, credentialScope, signature };
}
