import type { AiProviderKind } from "@bloody/contracts";
import { AiAbortError, AiProviderError, describeError } from "../errors.js";
import type { Clock, IdGenerator } from "../util/ids.js";
import { estimateMessagesTokens, estimateTokens } from "../util/tokens.js";
import type { HttpClient } from "./http.js";
import type { AiProvider, AiUsage, ChatRequest, ChatResponse, HealthStatus, ModelInfo, ServedBy } from "./types.js";

export interface ProviderCommon {
  id: string | null;
  kind: AiProviderKind;
  model: string;
  temperature: number;
  maxOutputTokens: number;
  contextWindow: number;
  http: HttpClient;
  ids: IdGenerator;
  clock: Clock;
}

export abstract class BaseProvider implements AiProvider {
  protected constructor(protected readonly common: ProviderCommon) {}

  get kind(): AiProviderKind {
    return this.common.kind;
  }
  get id(): string | null {
    return this.common.id;
  }
  get model(): string {
    return this.common.model;
  }
  protected get http(): HttpClient {
    return this.common.http;
  }

  abstract chat(req: ChatRequest): Promise<ChatResponse>;
  abstract listModels(signal?: AbortSignal): Promise<ModelInfo[]>;

  protected sampling(req: ChatRequest): { temperature: number; maxOutputTokens: number } {
    return {
      temperature: req.temperature ?? this.common.temperature,
      maxOutputTokens: Math.max(1, Math.floor(req.maxOutputTokens ?? this.common.maxOutputTokens)),
    };
  }

  protected servedBy(model?: string): ServedBy {
    return { providerId: this.id, kind: this.kind, model: model || this.model };
  }

  protected nowMs(): number {
    return this.common.clock.now().getTime();
  }

  protected usageOrEstimate(req: ChatRequest, content: string, input: number | undefined, output: number | undefined): AiUsage {
    if (input !== undefined && output !== undefined) return { inputTokens: input, outputTokens: output };
    return {
      inputTokens: input ?? estimateMessagesTokens(req.messages),
      outputTokens: output ?? estimateTokens(content),
      estimated: true,
    };
  }

  protected invalid(message: string, status?: number): AiProviderError {
    return new AiProviderError({ code: "invalid_response", message, providerKind: this.kind, providerId: this.id, status: status ?? null });
  }

  /** Whether a listed model id refers to the configured model (tolerates ":latest" / "models/" forms). */
  protected matchesModel(listed: string): boolean {
    const norm = (s: string): string => s.replace(/^models\//, "").replace(/:latest$/, "").toLowerCase();
    return norm(listed) === norm(this.model);
  }

  async healthCheck(signal?: AbortSignal): Promise<HealthStatus> {
    const started = this.nowMs();
    try {
      const models = await this.listModels(signal);
      return {
        ok: true,
        kind: this.kind,
        providerId: this.id,
        model: this.model,
        latencyMs: this.nowMs() - started,
        modelAvailable: models.length > 0 ? models.some((m) => this.matchesModel(m.id)) : null,
        modelsListed: models.length,
        checkedAt: this.common.clock.now().toISOString(),
      };
    } catch (err) {
      if (err instanceof AiAbortError) throw err;
      return {
        ok: false,
        kind: this.kind,
        providerId: this.id,
        model: this.model,
        latencyMs: this.nowMs() - started,
        modelAvailable: null,
        modelsListed: null,
        error: describeError(err),
        checkedAt: this.common.clock.now().toISOString(),
      };
    }
  }
}
