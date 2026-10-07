/**
 * @bloody/engines — Bloody's proprietary analytics core.
 *
 *   Security Graph   entity resolution, ingestion, relationship queries (store behind GraphStore)
 *   Risk Engine      explainable likelihood × impact model; asset / identity / incident /
 *                    vulnerability / exposure / attack-path scoring
 *   Attack Paths     k-shortest likely paths to crown jewels + greedy min-cut remediation
 *   Detection        detection-as-code: Sigma-subset compiler, threshold, sequence, IOC rules,
 *                    validation, tests, versioned registry, suppression & FP feedback
 *   Correlation      detections → explainable, risk-escalated incident drafts
 *   Reporting/Notify report-ready aggregates, audience narratives, automation notifications
 *
 * Pure TypeScript; all I/O (storage, clock, notifications, indicators) is injected.
 */

// util
export * from "./util/clock.js";
export * from "./util/ip.js";
export { uuidV5, stableId, contentHash, canonicalJson, BLOODY_UUID_NAMESPACE } from "./util/uuid.js";
export { clamp, clamp01, saturate, noisyOr, round, haversineKm } from "./util/math.js";

// entities & notifications
export * from "./entities/keys.js";
export * from "./notifications.js";

// security graph
export * from "./graph/types.js";
export * from "./graph/ids.js";
export * from "./graph/props.js";
export * from "./graph/traverse.js";
export * from "./graph/memory-store.js";
export * from "./graph/sql.js";
export * from "./graph/attack-semantics.js";
export * from "./graph/security-graph.js";

// risk
export * from "./risk/model.js";
export * from "./risk/tactics.js";
export * from "./risk/risk-engine.js";

// attack paths
export * from "./attack-path/engine.js";
export * from "./attack-path/remediation.js";

// detection
export * from "./detection/types.js";
export * from "./detection/field-mapping.js";
export * from "./detection/sigma/condition.js";
export * from "./detection/sigma/compiler.js";
export * from "./detection/sigma/sigma.js";
export * from "./detection/indicators.js";
export * from "./detection/suppression.js";
export * from "./detection/evaluators.js";
export * from "./detection/engine.js";
export * from "./detection/validate.js";
export * from "./detection/test-runner.js";
export * from "./detection/registry.js";

// correlation
export * from "./correlation/correlator.js";

// built-in rule pack
export * from "./rules/index.js";

// reporting helpers
export * from "./reporting/detection-report.js";
export * from "./reporting/narrative.js";
