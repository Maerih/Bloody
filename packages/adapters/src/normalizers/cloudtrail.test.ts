import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { assertSchemaValid, ctx, fixtureText } from "../test-support/fixtures.js";
import { createCloudTrailAdapter } from "./cloudtrail.js";

const adapter = createCloudTrailAdapter();
const events = adapter.normalize(fixtureText("cloudtrail/records.json"), ctx());
const [rootLogin, stopLogging, adminPolicy, denied, assumeRole] = events;

describe("AWS CloudTrail adapter", () => {
  it("unwraps Records[] and validates", () => {
    expect(events).toHaveLength(5);
    assertSchemaValid(events);
    expect(events.every((e) => e.source.product === "aws_cloudtrail" && e.source.kind === "cloud")).toBe(true);
  });

  it("root console login without MFA: authentication, raised to medium, explained", () => {
    expect(rootLogin?.category).toBe("authentication");
    expect(rootLogin?.severity).toBe("medium");
    expect(rootLogin?.identity).toMatchObject({ provider: "aws", principal: "arn:aws:iam::123456789012:root", privileged: true, mfa: false, outcome: "success" });
    expect(rootLogin?.labels["severity_basis"]).toBe("console login without MFA by the root user");
  });

  it("StopLogging is high with T1562.008 and the trail as resource", () => {
    expect(stopLogging?.severity).toBe("high");
    expect(stopLogging?.attack[0]).toEqual({ id: "T1562.008", name: "Disable or Modify Cloud Logs", tactic: "Defense Evasion" });
    expect(stopLogging?.cloudResource).toEqual({
      provider: "aws",
      accountId: "123456789012",
      region: "eu-west-1",
      resourceType: "AWS::CloudTrail::Trail",
      resourceId: "arn:aws:cloudtrail:eu-west-1:123456789012:trail/org-trail",
      action: "cloudtrail:StopLogging",
    });
  });

  it("AdministratorAccess attachment escalates to high; denied calls are failed attempts", () => {
    expect(adminPolicy?.category).toBe("identity");
    expect(adminPolicy?.severity).toBe("high");
    expect(adminPolicy?.labels["severity_basis"]).toContain("administrator access");
    expect(denied?.outcome).toBe("failure");
    expect(denied?.severity).toBe("medium");
    expect(denied?.labels["aws.error_code"]).toBe("AccessDenied");
    expect(denied?.indicators).toEqual([]);
    expect(assumeRole?.severity).toBe("info");
    expect(assumeRole?.network).toBeUndefined();
    expect(assumeRole?.labels["aws.source"]).toBe("ec2.amazonaws.com");
  });

  it("EventBridge envelopes and gzip log files; secret access keys never stored", () => {
    const [e] = adapter.normalize(fixtureText("cloudtrail/eventbridge.json"), ctx());
    expect(e?.eventType).toBe("aws.iam.CreateAccessKey");
    expect(e?.attack[0]?.id).toBe("T1098.001");
    expect(JSON.stringify(e)).not.toContain("never-store-this");
    const gz = adapter.normalize(gzipSync(Buffer.from(fixtureText("cloudtrail/records.json"))), ctx());
    expect(gz).toHaveLength(5);
  });
});
