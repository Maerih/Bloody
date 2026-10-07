import type { AiMessage } from "@bloody/contracts";
import { isRecord, safeJsonParse } from "../util/json.js";
import type { ToolSpec } from "./types.js";

export type AiToolCall = NonNullable<AiMessage["toolCalls"]>[number];

/** Marker key used when a model emits tool arguments that are not valid JSON. */
export const INVALID_TOOL_ARGUMENTS_KEY = "__invalid_json__";

/** Normalise tool-call arguments (JSON string or object) into a record. Invalid JSON is preserved
 * under {@link INVALID_TOOL_ARGUMENTS_KEY} so the gateway rejects it with a clear error. */
export function parseToolArguments(raw: unknown): Record<string, unknown> {
  if (raw === undefined || raw === null || raw === "") return {};
  if (isRecord(raw)) return raw;
  if (typeof raw === "string") {
    const parsed = safeJsonParse(raw);
    if (parsed.ok && isRecord(parsed.value)) return parsed.value;
    return { [INVALID_TOOL_ARGUMENTS_KEY]: raw.slice(0, 2000) };
  }
  return { [INVALID_TOOL_ARGUMENTS_KEY]: String(raw).slice(0, 2000) };
}

/** Find the tool name for a tool-result message by its call id (needed by Gemini / Ollama). */
export function toolNameForCall(messages: readonly AiMessage[], toolCallId: string | undefined): string | undefined {
  if (!toolCallId) return undefined;
  for (let i = messages.length - 1; i >= 0; i--) {
    const call = messages[i]?.toolCalls?.find((c) => c.id === toolCallId);
    if (call) return call.name;
  }
  return undefined;
}

/** Split leading/inline system messages from the conversation (Anthropic, Gemini, Bedrock). */
export function splitSystem(messages: readonly AiMessage[]): { system: string; rest: AiMessage[] } {
  const system: string[] = [];
  const rest: AiMessage[] = [];
  for (const m of messages) {
    if (m.role === "system") {
      if (m.content.trim()) system.push(m.content);
    } else {
      rest.push(m);
    }
  }
  return { system: system.join("\n\n"), rest };
}

export function toolResultValue(content: string): unknown {
  const parsed = safeJsonParse(content);
  return parsed.ok ? parsed.value : content;
}

/** OpenAI-style function tool declarations (OpenAI, Azure, vLLM, LM Studio, Mistral, Ollama). */
export function toFunctionTools(tools: readonly ToolSpec[]): Array<{ type: "function"; function: { name: string; description: string; parameters: Record<string, unknown> } }> {
  return tools.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.parameters } }));
}

export function makeToolCallId(prefix: string, ids: () => string): string {
  return `${prefix}_${ids().replace(/-/g, "").slice(0, 16)}`;
}
