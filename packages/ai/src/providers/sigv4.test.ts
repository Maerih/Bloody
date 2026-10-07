import { describe, expect, it } from "vitest";
import { canonicalUri, deriveSigningKey, formatAmzDate, sha256Hex, signSigV4 } from "./sigv4.js";

// Known-answer vectors from the AWS Signature Version 4 documentation / test suite.
const CREDS = { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" };
const NOW = new Date("2015-08-30T12:36:00Z");

describe("SigV4", () => {
  it("derives the documented signing key", () => {
    expect(deriveSigningKey(CREDS.secretAccessKey, "20150830", "us-east-1", "iam").toString("hex")).toBe(
      "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
    );
  });

  it("formats amz dates", () => {
    expect(formatAmzDate(NOW)).toEqual({ amzDate: "20150830T123600Z", dateStamp: "20150830" });
  });

  it("matches the IAM ListUsers example (canonical request, string to sign, signature)", () => {
    const res = signSigV4({
      method: "GET",
      url: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
      headers: { "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
      body: "",
      region: "us-east-1",
      service: "iam",
      credentials: CREDS,
      now: NOW,
    });
    expect(res.canonicalRequest).toBe(
      [
        "GET",
        "/",
        "Action=ListUsers&Version=2010-05-08",
        "content-type:application/x-www-form-urlencoded; charset=utf-8",
        "host:iam.amazonaws.com",
        "x-amz-date:20150830T123600Z",
        "",
        "content-type;host;x-amz-date",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      ].join("\n"),
    );
    expect(sha256Hex(res.canonicalRequest)).toBe("f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59");
    expect(res.stringToSign).toBe(
      "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\nf536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59",
    );
    expect(res.signature).toBe("5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
    expect(res.headers.authorization).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
    );
    expect(res.headers.host).toBeUndefined();
  });

  it("matches the aws-sig-v4 test-suite get-vanilla vector", () => {
    const res = signSigV4({ method: "GET", url: "https://example.amazonaws.com/", headers: {}, body: "", region: "us-east-1", service: "service", credentials: CREDS, now: NOW });
    expect(res.signature).toBe("5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
  });

  it("double-encodes path segments for non-S3 services (Bedrock model ids with ':')", () => {
    expect(canonicalUri("/model/anthropic.claude-3-5-sonnet-20240620-v1%3A0/converse", true)).toBe("/model/anthropic.claude-3-5-sonnet-20240620-v1%253A0/converse");
    expect(canonicalUri("/a%20b", false)).toBe("/a%20b");
  });

  it("adds the session token and signs it", () => {
    const res = signSigV4({ method: "POST", url: "https://bedrock-runtime.us-east-1.amazonaws.com/model/x/converse", headers: { "content-type": "application/json" }, body: "{}", region: "us-east-1", service: "bedrock", credentials: { ...CREDS, sessionToken: "TOKEN" }, now: NOW });
    expect(res.headers["x-amz-security-token"]).toBe("TOKEN");
    expect(res.signedHeaders).toBe("content-type;host;x-amz-date;x-amz-security-token");
  });
});
