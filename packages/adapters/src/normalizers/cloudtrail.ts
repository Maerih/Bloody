import type { EventCategory, Severity } from "@bloody/contracts";
import { technique } from "../core/attack.js";
import { defineAdapter, skip, type Adapter, type AdapterExtras, type MapOutput } from "../core/adapter.js";
import { ObservableSet } from "../core/indicators.js";
import { arr, bool, field, isRecord, rec, redactKeys, str, truncate } from "../core/json.js";
import { jsonRecords } from "../core/records.js";
import { atLeast, DEFAULT_SENSITIVE_KEYS } from "../core/severity.js";
import { toIso } from "../core/time.js";
import { isIp } from "../net/ip.js";

/**
 * AWS CloudTrail adapter — consumes CloudTrail log files (`{"Records":[…]}`, gzip OK),
 * EventBridge `detail` envelopes, CloudTrail Lake rows and single records.
 *
 * Sensitive control-plane APIs (log tampering, detector deletion, credential creation,
 * policy attachment, MFA removal, public bucket policies, KMS key deletion, snapshot sharing)
 * carry curated severities and ATT&CK techniques; root-user activity is raised to medium;
 * access-denied errors are kept as failed attempts (permission probing).
 */
export const CLOUDTRAIL_ADAPTER_VERSION = "1.0.0";

interface ApiSpec {
  severity: Severity;
  attack?: string;
  why: string;
  category?: EventCategory;
}

const SENSITIVE: Record<string, ApiSpec> = {
  "cloudtrail:StopLogging": { severity: "high", attack: "T1562.008", why: "CloudTrail logging stopped" },
  "cloudtrail:DeleteTrail": { severity: "high", attack: "T1562.008", why: "CloudTrail trail deleted" },
  "cloudtrail:UpdateTrail": { severity: "medium", attack: "T1562.008", why: "CloudTrail trail modified" },
  "cloudtrail:PutEventSelectors": { severity: "medium", attack: "T1562.008", why: "CloudTrail event selectors changed" },
  "config:StopConfigurationRecorder": { severity: "high", attack: "T1562.008", why: "AWS Config recorder stopped" },
  "config:DeleteConfigurationRecorder": { severity: "high", attack: "T1562.008", why: "AWS Config recorder deleted" },
  "config:DeleteDeliveryChannel": { severity: "high", attack: "T1562.008", why: "AWS Config delivery channel deleted" },
  "guardduty:DeleteDetector": { severity: "high", attack: "T1562.001", why: "GuardDuty detector deleted" },
  "guardduty:UpdateDetector": { severity: "medium", attack: "T1562.001", why: "GuardDuty detector modified" },
  "guardduty:DisassociateFromMasterAccount": { severity: "high", attack: "T1562.001", why: "GuardDuty disassociated from administrator" },
  "ec2:DeleteFlowLogs": { severity: "high", attack: "T1562.008", why: "VPC flow logs deleted" },
  "logs:DeleteLogGroup": { severity: "medium", attack: "T1070", why: "CloudWatch log group deleted" },
  "logs:DeleteLogStream": { severity: "medium", attack: "T1070", why: "CloudWatch log stream deleted" },
  "iam:CreateUser": { severity: "low", attack: "T1136.003", why: "IAM user created", category: "identity" },
  "iam:CreateAccessKey": { severity: "medium", attack: "T1098.001", why: "IAM access key created", category: "identity" },
  "iam:CreateLoginProfile": { severity: "medium", attack: "T1098", why: "console password set for IAM user", category: "identity" },
  "iam:UpdateLoginProfile": { severity: "medium", attack: "T1098", why: "console password changed for IAM user", category: "identity" },
  "iam:AttachUserPolicy": { severity: "medium", attack: "T1098.003", why: "managed policy attached to user", category: "identity" },
  "iam:AttachRolePolicy": { severity: "medium", attack: "T1098.003", why: "managed policy attached to role", category: "identity" },
  "iam:AttachGroupPolicy": { severity: "medium", attack: "T1098.003", why: "managed policy attached to group", category: "identity" },
  "iam:PutUserPolicy": { severity: "medium", attack: "T1098.003", why: "inline policy put on user", category: "identity" },
  "iam:PutRolePolicy": { severity: "medium", attack: "T1098.003", why: "inline policy put on role", category: "identity" },
  "iam:PutGroupPolicy": { severity: "medium", attack: "T1098.003", why: "inline policy put on group", category: "identity" },
  "iam:CreatePolicyVersion": { severity: "medium", attack: "T1098.003", why: "policy version created", category: "identity" },
  "iam:UpdateAssumeRolePolicy": { severity: "high", attack: "T1098.003", why: "role trust policy changed", category: "identity" },
  "iam:AddUserToGroup": { severity: "low", attack: "T1098", why: "user added to IAM group", category: "identity" },
  "iam:DeactivateMFADevice": { severity: "high", attack: "T1556.006", why: "MFA device deactivated", category: "identity" },
  "iam:DeleteVirtualMFADevice": { severity: "high", attack: "T1556.006", why: "virtual MFA device deleted", category: "identity" },
  "s3:PutBucketPolicy": { severity: "medium", attack: "T1530", why: "bucket policy changed" },
  "s3:PutBucketAcl": { severity: "medium", attack: "T1530", why: "bucket ACL changed" },
  "s3:DeleteBucketPolicy": { severity: "medium", attack: "T1530", why: "bucket policy deleted" },
  "s3:DeleteBucketPublicAccessBlock": { severity: "high", attack: "T1530", why: "bucket public access block removed" },
  "s3:PutBucketPublicAccessBlock": { severity: "medium", attack: "T1530", why: "bucket public access block changed" },
  "s3control:DeletePublicAccessBlock": { severity: "high", attack: "T1530", why: "account public access block removed" },
  "s3:DeleteBucketEncryption": { severity: "medium", attack: "T1562", why: "bucket default encryption removed" },
  "kms:ScheduleKeyDeletion": { severity: "high", attack: "T1485", why: "KMS key scheduled for deletion" },
  "kms:DisableKey": { severity: "high", attack: "T1485", why: "KMS key disabled" },
  "ec2:ModifySnapshotAttribute": { severity: "high", attack: "T1537", why: "EBS snapshot sharing changed" },
  "rds:ModifyDBSnapshotAttribute": { severity: "high", attack: "T1537", why: "RDS snapshot sharing changed" },
  "ec2:AuthorizeSecurityGroupIngress": { severity: "low", attack: "T1562.007", why: "security group ingress opened" },
  "ec2:CreateKeyPair": { severity: "low", attack: "T1098", why: "EC2 key pair created" },
  "ec2:ImportKeyPair": { severity: "low", attack: "T1098", why: "EC2 key pair imported" },
  "ec2:GetPasswordData": { severity: "medium", attack: "T1552", why: "Windows instance password retrieved" },
  "organizations:LeaveOrganization": { severity: "high", attack: "T1562", why: "account left AWS Organization" },
  "secretsmanager:GetSecretValue": { severity: "info", attack: "T1555", why: "secret read" },
  "lambda:UpdateFunctionCode": { severity: "low", attack: "T1648", why: "Lambda function code updated" },
  "lambda:CreateFunction": { severity: "low", attack: "T1648", why: "Lambda function created" },
};

const RESOURCE_PARAM_KEYS = ["bucketName", "userName", "roleName", "groupName", "instanceId", "functionName", "keyId", "trailName", "name", "detectorId", "snapshotId", "dBSnapshotIdentifier", "secretId", "policyArn"];

function serviceOf(eventSource: string): string {
  return eventSource.replace(/\.amazonaws\.com$/, "");
}

function mapRecord(record: unknown): MapOutput {
  if (!isRecord(record)) return skip("not a JSON object");
  const r = rec(record["detail"]) && str(record["detail-type"])?.includes("AWS API Call") ? rec(record["detail"])! : record;
  const eventSource = str(r["eventSource"]);
  const eventName = str(r["eventName"]);
  if (!eventSource || !eventName) return skip("not a CloudTrail record (eventSource/eventName missing)");
  const service = serviceOf(eventSource);
  const key = `${service}:${eventName}`;
  const ui = rec(r["userIdentity"]) ?? {};
  const uiType = str(ui["type"]);
  const arn = str(ui["arn"]);
  const userName = str(ui["userName"]) ?? str(field(ui, "sessionContext.sessionIssuer.userName")) ?? str(ui["principalId"]);
  const sourceIp = str(r["sourceIPAddress"]);
  const ip = sourceIp && isIp(sourceIp) ? sourceIp : undefined;
  const errorCode = str(r["errorCode"]);
  const failed = errorCode !== undefined;
  const isRoot = uiType === "Root";
  const mfa =
    bool(field(ui, "sessionContext.attributes.mfaAuthenticated")) ??
    (str(field(r, "additionalEventData.MFAUsed")) ? str(field(r, "additionalEventData.MFAUsed")) === "Yes" : undefined);
  const resource = arr(r["resources"]).find(isRecord);
  const params = rec(r["requestParameters"]) ?? {};
  const paramResource = RESOURCE_PARAM_KEYS.map((k) => str(params[k])).find((v) => v !== undefined);
  const obs = new ObservableSet().add("ip", ip);
  const labels: Record<string, string | number | boolean | undefined> = {
    "aws.event_source": eventSource,
    "aws.event_category": str(r["eventCategory"]),
    "aws.read_only": bool(r["readOnly"]),
    "aws.user_agent": str(r["userAgent"]),
    "aws.identity_type": uiType,
    "aws.access_key_id": str(ui["accessKeyId"]),
    "aws.error_code": errorCode,
    "aws.error_message": str(r["errorMessage"]) ? truncate(str(r["errorMessage"])!, 300) : undefined,
    "aws.source": sourceIp && !ip ? sourceIp : undefined,
    "aws.event_type": str(r["eventType"]),
  };

  let category: EventCategory = "cloud";
  let severity: Severity = "info";
  let attackId: string | undefined;
  let why: string | undefined;
  let outcome: "success" | "failure" = failed ? "failure" : "success";

  if (key === "signin:ConsoleLogin") {
    category = "authentication";
    const result = str(field(r, "responseElements.ConsoleLogin"));
    outcome = result === "Success" && !failed ? "success" : "failure";
    severity = outcome === "failure" ? "low" : "info";
    why = outcome === "failure" ? "console login failed" : mfa === false ? "console login without MFA" : "console login";
    if (outcome === "success" && mfa === false) severity = "low";
    if (outcome === "failure") attackId = "T1110";
  } else {
    const spec = SENSITIVE[key];
    if (spec) {
      severity = spec.severity;
      attackId = spec.attack;
      why = spec.why;
      if (spec.category) category = spec.category;
    } else if (service === "iam" || service === "sts" || service === "sso" || service === "identitystore") {
      category = "identity";
    }
    if ((key.startsWith("iam:Attach") || key.startsWith("iam:Put")) && /AdministratorAccess|"\*"|:\*"/.test(JSON.stringify(params))) {
      severity = "high";
      why = `${why ?? "policy change"} granting administrator access`;
    }
  }
  if (isRoot) {
    severity = atLeast(severity, "medium");
    why = `${why ?? key} by the root user`;
  }
  if (failed && /AccessDenied|UnauthorizedOperation|Unauthorized/i.test(errorCode ?? "")) {
    severity = atLeast(severity, "low");
    why = `${why ?? key} denied (${errorCode})`;
  }
  labels["severity_basis"] = why ?? "routine API call";
  const t = attackId ? technique(attackId) : undefined;
  const accountId = str(r["recipientAccountId"]) ?? str(ui["accountId"]);
  return {
    timestamp: toIso(r["eventTime"]),
    category,
    eventType: `aws.${service}.${eventName}`,
    action: key,
    outcome,
    message: `${eventName} by ${arn ?? userName ?? uiType ?? "unknown principal"}${why ? ` — ${why}` : ""}`,
    severity,
    user: userName ? { name: userName } : undefined,
    identity: { provider: "aws", principal: arn ?? userName, sourceIp: ip, privileged: isRoot ? true : undefined, mfa, outcome },
    network: ip ? { srcIp: ip } : undefined,
    cloudResource: {
      provider: "aws",
      accountId,
      region: str(r["awsRegion"]),
      resourceType: str(resource?.["type"]) ?? service,
      resourceId: str(resource?.["ARN"]) ?? paramResource,
      action: key,
    },
    indicators: obs.toArray(),
    attack: t ? [t] : [],
    labels,
    dedupKey: str(r["eventID"]) ?? `${str(r["eventTime"]) ?? ""}:${key}:${arn ?? ""}`,
    source: { kind: "cloud", product: "aws_cloudtrail", vendor: "Amazon Web Services" },
    raw: redactKeys(r, DEFAULT_SENSITIVE_KEYS),
  };
}

export function createCloudTrailAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "aws_cloudtrail",
    version: CLOUDTRAIL_ADAPTER_VERSION,
    name: "AWS CloudTrail",
    sourceKind: "cloud",
    product: "aws_cloudtrail",
    vendor: "Amazon Web Services",
    consumes: ["CloudTrail log files {Records:[…]} (gzip)", "EventBridge 'AWS API Call via CloudTrail' events", "single CloudTrail records"],
    split: (raw) => jsonRecords(raw, { unwrap: (o) => (Array.isArray(o["Records"]) ? o["Records"] : undefined) }),
    map: mapRecord,
  });
}
