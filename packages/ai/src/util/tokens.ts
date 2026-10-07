import type { AiMessage } from "@bloody/contracts";

/**
 * Provider-agnostic token estimate (~4 characters per token for English/JSON). Used only for
 * context-window fitting and budget guards before the provider reports exact usage.
 */
export function estimateTokens(text: string): number {
  if (!text) return 0;
  return Math.ceil(text.length / 4);
}

const MESSAGE_OVERHEAD_TOKENS = 4;

export function estimateMessageTokens(message: AiMessage): number {
  let tokens = MESSAGE_OVERHEAD_TOKENS + estimateTokens(message.content);
  if (message.toolCalls) {
    for (const call of message.toolCalls) tokens += estimateTokens(call.name) + estimateTokens(JSON.stringify(call.arguments)) + 4;
  }
  return tokens;
}

export function estimateMessagesTokens(messages: readonly AiMessage[]): number {
  return messages.reduce((sum, m) => sum + estimateMessageTokens(m), 0);
}
