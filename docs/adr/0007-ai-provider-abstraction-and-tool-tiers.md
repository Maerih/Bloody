# ADR-0007: AI provider abstraction and tool permission tiers

- Status: Accepted
- Date: 2026-10-07
- Deciders: AI engineering, security engineering, product

## Context

The AI SOC analyst summarizes incidents, investigates, hunts, drafts detections and reports, and
proposes responses. Customers differ sharply in what they allow:

- some require **local models only**: data must not leave their environment, or an air-gapped
  deployment is planned;
- others standardize on one cloud provider (OpenAI, Anthropic, Google, Azure OpenAI, AWS
  Bedrock, Mistral);
- MSSPs need per-customer policies.

An LLM with tools is also an attack surface. Prompt injection can arrive inside the very
telemetry it reads (log lines, phishing e-mails, file names), and a model must never be able to
isolate a host or disable an identity on its own say-so.

## Decision

1. **Provider abstraction** (`@bloody/ai`, `createProvider(config, fetch)`).
   - Supported kinds (`AiProviderKind`):
     - local: Ollama, vLLM, LM Studio, any OpenAI-compatible endpoint;
     - cloud: OpenAI, Anthropic, Google, Azure OpenAI, AWS Bedrock (SigV4) and Mistral.
   - Providers are configured **per tenant or per organization** (`AiProviderConfig`): endpoint,
     model, context window, temperature, max output, system policy, `maxToolTier`, default and
     **fallback** provider, retention days.
   - Nothing in the product is hard-coded to a vendor.
2. **Privacy by default.**
   - `allowCloudData = false`: tenant data is refused for cloud providers unless explicitly
     enabled (`assertTenantDataAllowed`).
   - `redactSensitive = true`: secrets, credentials and PII are redacted before context leaves
     the platform.
   - Prompt and response retention is configurable down to 0 days.
   - API keys are write-only: they are stored encrypted (AES-256-GCM `credentialRef`) and never
     returned.
3. **Egress safety.**
   - Provider endpoints pass an SSRF guard. Link-local and cloud-metadata ranges are always
     blocked; private ranges are allowed only when the deployment enables local models
     (`BLOODY_AI_ALLOW_PRIVATE_ENDPOINTS`).
   - Kubernetes NetworkPolicies block private ranges and metadata as defence in depth.
4. **Tool tiers** (`AiToolTier`, least to most privileged): `read` → `investigate` →
   `recommend` → `require_approval` → `execute`. The **ToolGateway** is the only path from a
   model to data or actions. For every call it:
   1. resolves the tool (unknown tools are denied);
   2. checks tenant and RBAC (`ai:use` plus the tool's own permission, per organization);
   3. validates arguments with the tool's zod schema;
   4. applies the tier policy against the serving model's `maxToolTier`
      (default `recommend`):
      - `require_approval` actions are **always** queued for a human;
      - `execute` runs autonomously only when `maxToolTier = execute` *and* the action is
        low-risk;
   5. writes an **audit record before executing** (fail closed if audit is unavailable) and
      another with the outcome.

   Approved actions execute later through the SOAR approval gate (ADR-0008), with four-eyes
   (distinct approver) by default.
5. **Grounding.** Context is built only from the requesting tenant's data, via tenant-scoped
   queries. Tool results are size-capped and marked as data, not instructions. The base SOC
   policy (`BLOODY_BASE_SOC_POLICY`, versioned) is prepended to every customer system policy and
   cannot be removed by it.
6. **Usage metering.** AI requests count against plan limits (`aiRequestsPerDay`) and
   per-organization usage counters. They are billed via entitlements, not tied to security logic.

## Consequences

- Customers choose local-only, cloud, or hybrid with a fallback, per organization. MSSPs set the
  policy per customer.
- A successful prompt injection is bounded by the tier, RBAC and approval gate: the worst
  autonomous outcome is a low-risk action the customer explicitly allowed.
- Each provider adapter must be maintained as vendor APIs change. Provider tests use recorded
  HTTP fixtures; there are no live calls in CI.
- Local-model quality and availability vary. When the primary provider fails, the orchestrator
  switches to the configured fallback provider and records `fallbackUsed`. With no provider
  available, AI features fail visibly, while incidents, risk factors and timelines remain fully
  usable without AI.

## Alternatives considered

- **Single-vendor SDK.** Lock-in, and unusable for local-only or air-gapped customers. Rejected.
- **LangChain-style framework as the core.** Heavy, fast-moving dependency surface, and its
  permission model does not match our RBAC and approval semantics. Our gateway is small and
  auditable.
- **Letting models call the REST API with a user token.** This would bypass tool schemas, tiers
  and pre-execution audit. Rejected.
