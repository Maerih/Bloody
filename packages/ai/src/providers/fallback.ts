import { AiAbortError, AiProviderError, describeError } from "../errors.js";
import type { AiProvider, ChatRequest, ChatResponse, HealthStatus, ModelInfo, ProviderAttempt } from "./types.js";

export interface FallbackEvent {
  from: { providerId: string | null; kind: AiProvider["kind"]; model: string };
  to: { providerId: string | null; kind: AiProvider["kind"]; model: string };
  error: { code: string; message: string };
}

/**
 * Tries providers in order (primary → fallbackProviderId chain) on errors, timeouts and policy
 * refusals. Never falls back on caller aborts, and never after a streamed answer has started
 * (the caller would otherwise see two interleaved answers).
 */
export class FallbackProvider implements AiProvider {
  private readonly chain: AiProvider[];

  constructor(
    chain: AiProvider[],
    private readonly onFallback?: (event: FallbackEvent) => void,
  ) {
    if (chain.length === 0) throw new Error("FallbackProvider requires at least one provider");
    this.chain = chain;
  }

  get kind(): AiProvider["kind"] {
    return this.chain[0]!.kind;
  }
  get id(): string | null {
    return this.chain[0]!.id;
  }
  get model(): string {
    return this.chain[0]!.model;
  }
  get providers(): readonly AiProvider[] {
    return this.chain;
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const attempts: ProviderAttempt[] = [];
    let lastError: unknown;
    for (let i = 0; i < this.chain.length; i++) {
      const provider = this.chain[i]!;
      let streamed = false;
      const onDelta = req.onDelta
        ? (text: string): void => {
            streamed = true;
            req.onDelta!(text);
          }
        : undefined;
      try {
        const res = await provider.chat({ ...req, ...(onDelta ? { onDelta } : {}) });
        attempts.push({ providerId: provider.id, kind: provider.kind, model: provider.model, ok: true });
        return { ...res, attempts, fallbackUsed: i > 0 };
      } catch (err) {
        if (err instanceof AiAbortError) throw err;
        const described = describeError(err);
        attempts.push({ providerId: provider.id, kind: provider.kind, model: provider.model, ok: false, error: described });
        lastError = err;
        const next = this.chain[i + 1];
        if (!next || streamed) break;
        this.onFallback?.({
          from: { providerId: provider.id, kind: provider.kind, model: provider.model },
          to: { providerId: next.id, kind: next.kind, model: next.model },
          error: described,
        });
      }
    }
    if (attempts.length === 1) throw lastError;
    throw new AiProviderError({
      code: "all_providers_failed",
      message: `All AI providers failed: ${attempts.map((a) => `${a.kind}(${a.error?.code ?? "?"})`).join(", ")}`,
      providerKind: this.kind,
      providerId: this.id,
      cause: lastError,
      details: { attempts },
    });
  }

  listModels(signal?: AbortSignal): Promise<ModelInfo[]> {
    return this.chain[0]!.listModels(signal);
  }

  healthCheck(signal?: AbortSignal): Promise<HealthStatus> {
    return this.chain[0]!.healthCheck(signal);
  }
}
