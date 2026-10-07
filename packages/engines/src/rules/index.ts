import { DetectionRuleSchema, type DetectionRule, type DetectionRuleInput } from "../detection/types.js";
import { ENDPOINT_RULES } from "./endpoint.js";
import { IDENTITY_RULES } from "./identity.js";
import { NETWORK_RULES } from "./network.js";

export * from "./endpoint.js";
export * from "./identity.js";
export * from "./network.js";

/** Rule definitions as authored (inputs, defaults not yet applied). */
export const BUILTIN_RULE_DEFINITIONS: readonly DetectionRuleInput[] = [...ENDPOINT_RULES, ...IDENTITY_RULES, ...NETWORK_RULES];

/** Built-in Bloody rule pack, schema-validated with defaults applied. */
export const BUILTIN_RULES: readonly DetectionRule[] = BUILTIN_RULE_DEFINITIONS.map((r) => DetectionRuleSchema.parse(r));
