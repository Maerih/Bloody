import type { AiMessage, AiProviderConfig } from "@bloody/contracts";
import { assertTenantDataAllowed, classifyEgress, type DataEgress } from "../safety/egress.js";
import { RedactionVault, Redactor, StreamingRehydrator, emptyRedactionStats, type RedactionStats } from "../safety/redact.js";
import { safeJsonParse } from "../util/json.js";
import type { AiProvider, ChatRequest, ChatResponse, HealthStatus, ModelInfo } from "./types.js";

/**
 * Data-governance wrapper applied to every configured provider:
 *  - refuses tenant data for disabled providers and for cloud providers with allowCloudData=false;
 *  - when `redactSensitive` is on, redacts secrets for every provider and personal data (e-mail,
 *    cards, SSN, IBAN) for cloud providers, across messages, tool-call arguments and tool results;
 *  - re-hydrates placeholders echoed by the model (answer text, streamed deltas and tool-call
 *    arguments) so investigations keep working while the model never sees the raw values.
 */
export interface GovernanceOptions {
  /** Override PII redaction (default: on for cloud egress, off for local). */
  redactPii?: boolean;
  /** Re-hydrate placeholders in the model output (default true). */
  rehydrateOutput?: boolean;
}

export type GovernedConfig = Pick<AiProviderConfig, "id" | "name" | "kind" | "endpoint" | "enabled" | "allowCloudData" | "redactSensitive">;

export class GovernedProvider implements AiProvider {
  readonly egress: DataEgress;
  private readonly redactor: Redactor | null;
  private readonly rehydrateOutput: boolean;

  constructor(
    private readonly inner: AiProvider,
    private readonly config: GovernedConfig,
    options: GovernanceOptions = {},
  ) {
    this.egress = classifyEgress(config.kind, config.endpoint);
    const pii = options.redactPii ?? this.egress === "cloud";
    this.redactor = config.redactSensitive ? new Redactor({ secrets: true, pii, emails: pii }) : null;
    this.rehydrateOutput = options.rehydrateOutput ?? true;
  }

  get kind(): AiProvider["kind"] {
    return this.inner.kind;
  }
  get id(): string | null {
    return this.inner.id;
  }
  get model(): string {
    return this.inner.model;
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    if ((req.dataClass ?? "tenant") === "tenant") assertTenantDataAllowed(this.config);
    if (!this.redactor) {
      const res = await this.inner.chat(req);
      return { ...res, redactions: emptyRedactionStats() };
    }
    const vault = req.redactionVault ?? new RedactionVault();
    const stats: RedactionStats = emptyRedactionStats();
    const messages = req.messages.map((m) => this.redactMessage(m, vault, stats));
    let rehydrator: StreamingRehydrator | null = null;
    let onDelta = req.onDelta;
    if (req.onDelta && this.rehydrateOutput) {
      rehydrator = new StreamingRehydrator(vault, req.onDelta);
      onDelta = (text) => rehydrator!.push(text);
    }
    const res = await this.inner.chat({ ...req, messages, redactionVault: vault, ...(onDelta ? { onDelta } : {}) });
    rehydrator?.flush();
    const message: AiMessage = this.rehydrateOutput
      ? {
          ...res.message,
          content: vault.rehydrate(res.message.content),
          ...(res.message.toolCalls ? { toolCalls: res.message.toolCalls.map((c) => ({ ...c, arguments: vault.rehydrateValue(c.arguments) })) } : {}),
        }
      : res.message;
    return { ...res, message, redactions: stats };
  }

  private redactMessage(m: AiMessage, vault: RedactionVault, stats: RedactionStats): AiMessage {
    const redactor = this.redactor!;
    let content: string;
    const parsed = m.role === "tool" ? safeJsonParse(m.content) : null;
    if (parsed?.ok && typeof parsed.value === "object" && parsed.value !== null) {
      // Structured tool results: key-aware deep redaction (e.g. {"password": "…"}).
      content = JSON.stringify(redactor.redactValue(parsed.value, vault, stats));
    } else {
      content = redactor.redactText(m.content, vault, stats);
    }
    const out: AiMessage = { ...m, content };
    if (m.toolCalls) out.toolCalls = m.toolCalls.map((c) => ({ ...c, arguments: redactor.redactValue(c.arguments, vault, stats) }));
    return out;
  }

  listModels(signal?: AbortSignal): Promise<ModelInfo[]> {
    return this.inner.listModels(signal);
  }

  healthCheck(signal?: AbortSignal): Promise<HealthStatus> {
    return this.inner.healthCheck(signal);
  }
}
