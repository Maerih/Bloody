import { z } from "zod";

/**
 * Response shapes of the SOCFortress CoPilot REST API (`/api/...`), written from its public
 * endpoint contracts. CoPilot is AGPL-3.0 and runs as a separate, unmodified service; Bloody
 * only consumes these JSON responses. Schemas are lenient (passthrough, nullable) so minor
 * CoPilot upgrades do not break the sync, while the fields we rely on are type-checked.
 */

const nstr = z.string().nullish();
const id = z.union([z.number(), z.string()]).transform((v) => String(v));

export const CoPilotTokenResponse = z
  .object({
    access_token: z.string().min(10),
    token_type: z.string().optional(),
    requires_2fa: z.boolean().optional(),
  })
  .passthrough();

export const CoPilotCustomer = z
  .object({
    customer_code: z.string().min(1),
    customer_name: nstr,
    parent_customer_code: nstr,
    contact_first_name: nstr,
    contact_last_name: nstr,
    phone: nstr,
    city: nstr,
    state: nstr,
    country: nstr,
    customer_type: nstr,
    is_provisioned: z.boolean().nullish(),
  })
  .passthrough();
export type CoPilotCustomer = z.infer<typeof CoPilotCustomer>;

export const CoPilotCustomersResponse = z.object({ customers: z.array(CoPilotCustomer), success: z.boolean().optional(), message: z.string().optional() }).passthrough();

export const CoPilotAgent = z
  .object({
    id: id.nullish(),
    agent_id: z.string().min(1),
    hostname: nstr,
    ip_address: nstr,
    os: nstr,
    label: nstr,
    critical_asset: z.boolean().nullish(),
    wazuh_last_seen: nstr,
    wazuh_agent_version: nstr,
    wazuh_agent_status: nstr,
    velociraptor_id: nstr,
    velociraptor_last_seen: nstr,
    velociraptor_agent_version: nstr,
    velociraptor_org: nstr,
    customer_code: nstr,
    quarantined: z.boolean().nullish(),
  })
  .passthrough();
export type CoPilotAgent = z.infer<typeof CoPilotAgent>;

export const CoPilotAgentsResponse = z.object({ agents: z.array(CoPilotAgent).nullish(), success: z.boolean().optional(), message: z.string().optional() }).passthrough();

const CoPilotAlertAsset = z
  .object({
    id: id.nullish(),
    asset_name: nstr,
    agent_id: nstr,
    velociraptor_id: nstr,
    customer_code: nstr,
    index_name: nstr,
    index_id: nstr,
  })
  .passthrough();

const CoPilotIoc = z.object({ id: id.nullish(), value: z.string(), type: z.string(), description: nstr }).passthrough();

const CoPilotLinkedCase = z.object({ id: id, case_name: nstr, case_status: nstr, case_creation_time: nstr, assigned_to: nstr }).passthrough();

const CoPilotComment = z.object({ id: id.nullish(), user_name: nstr, comment: nstr, created_at: nstr }).passthrough();

export const CoPilotAlert = z
  .object({
    id: id,
    alert_name: z.string(),
    alert_description: nstr,
    alert_creation_time: nstr,
    time_closed: nstr,
    status: z.string(),
    customer_code: z.string(),
    source: nstr,
    severity: nstr,
    assigned_to: nstr,
    escalated: z.boolean().nullish(),
    verdict: nstr,
    verdict_reason: nstr,
    verdict_at: nstr,
    comments: z.array(CoPilotComment).nullish(),
    assets: z.array(CoPilotAlertAsset).nullish(),
    tags: z.array(z.object({ tag: z.string(), id: id.nullish() }).passthrough()).nullish(),
    linked_cases: z.array(CoPilotLinkedCase).nullish(),
    iocs: z.array(CoPilotIoc).nullish(),
  })
  .passthrough();
export type CoPilotAlert = z.infer<typeof CoPilotAlert>;

export const CoPilotAlertsResponse = z
  .object({
    alerts: z.array(CoPilotAlert),
    total: z.number().nullish(),
    open: z.number().nullish(),
    in_progress: z.number().nullish(),
    closed: z.number().nullish(),
    pending_customer: z.number().nullish(),
    success: z.boolean().optional(),
    message: z.string().optional(),
  })
  .passthrough();

export const CoPilotCase = z
  .object({
    id: id,
    case_name: z.string(),
    case_description: nstr,
    assigned_to: nstr,
    alerts: z.array(CoPilotAlert).nullish(),
    case_status: nstr,
    case_creation_time: nstr,
    customer_code: nstr,
    escalated: z.boolean().nullish(),
    severity: nstr,
    notification_invoked_number: z.number().nullish(),
  })
  .passthrough();
export type CoPilotCase = z.infer<typeof CoPilotCase>;

export const CoPilotCasesResponse = z
  .object({ cases: z.array(CoPilotCase), total: z.number().nullish(), success: z.boolean().optional(), message: z.string().optional() })
  .passthrough();

export const CoPilotUser = z
  .object({
    id: id,
    username: z.string(),
    email: nstr,
    role_id: z.number().nullish(),
    role_name: nstr,
    last_login_at: nstr,
  })
  .passthrough();
export type CoPilotUser = z.infer<typeof CoPilotUser>;

export const CoPilotUsersResponse = z.object({ users: z.array(CoPilotUser), success: z.boolean().optional() }).passthrough();

export const CoPilotCustomerCodesResponse = z
  .object({ customer_codes: z.array(z.string()), scope: z.string().optional(), success: z.boolean().optional() })
  .passthrough();

/** CoPilot role ids (RoleEnum): admin=1, analyst=2, scheduler=3, customer_user=4. */
export const COPILOT_CUSTOMER_USER_ROLE_ID = 4;
