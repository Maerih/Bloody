import { clsx } from "clsx";
import { Braces, Plus, Search, SlidersHorizontal, X } from "lucide-react";
import { useEffect, useId, useState, type FormEvent, type ReactNode } from "react";
import {
  EVENT_FIELDS,
  QUERY_OP_LABELS,
  QUERY_OPS,
  clauseIsComplete,
  fieldDef,
  isValidField,
  parseQuery,
  serializeClause,
  serializeQuery,
  type QueryClause,
  type QueryOp,
} from "../lib/eventQuery";
import { Button, IconButton } from "./Button";
import { Input, Select, Textarea } from "./Form";

export interface QueryBuilderProps {
  /** Current raw query (Bloody syntax). */
  value: string;
  /** Called when the analyst runs the search. */
  onSubmit: (query: string) => void;
  /** Extra controls next to the Search button (time range…). */
  actions?: ReactNode;
  placeholder?: string;
  className?: string;
}

const NUMERIC_OPS: QueryOp[] = ["eq", "neq", "gt", "gte", "lt", "lte", "in", "exists"];
const TEXT_OPS: QueryOp[] = ["eq", "neq", "contains", "in", "exists"];

function opsFor(field: string): QueryOp[] {
  const def = fieldDef(field);
  if (!def) return [...QUERY_OPS];
  if (def.type === "number") return NUMERIC_OPS;
  if (def.type === "enum" || def.type === "boolean") return ["eq", "neq", "in", "exists"];
  return TEXT_OPS;
}

/**
 * SIEM query builder: field / operator / value chips that serialize to Bloody query syntax,
 * with a raw-query mode for constructs the chips cannot express (OR, grouping). Switching back
 * to chips re-parses the raw query when possible.
 */
export function QueryBuilder({ value, onSubmit, actions, placeholder = "Free text, e.g. mimikatz", className }: QueryBuilderProps) {
  const parsed = parseQuery(value);
  const [mode, setMode] = useState<"builder" | "raw">(parsed ? "builder" : "raw");
  const [clauses, setClauses] = useState<QueryClause[]>(parsed?.clauses ?? []);
  const [freeText, setFreeText] = useState(parsed?.freeText ?? "");
  const [raw, setRaw] = useState(value);
  const [draft, setDraft] = useState<QueryClause>({ field: "category", op: "eq", value: "" });
  const [rawError, setRawError] = useState<string | null>(null);
  const listId = useId();

  // External changes (saved search, pivot links) replace the local state.
  useEffect(() => {
    const p = parseQuery(value);
    setRaw(value);
    if (p) {
      setClauses(p.clauses);
      setFreeText(p.freeText);
    } else {
      setMode("raw");
    }
  }, [value]);

  const builderQuery = serializeQuery(clauses, freeText);

  const addDraft = () => {
    if (!clauseIsComplete(draft)) return;
    setClauses((c) => [...c, { ...draft, value: draft.value.trim() }]);
    setDraft((d) => ({ ...d, value: "" }));
  };

  const switchMode = (next: "builder" | "raw") => {
    if (next === mode) return;
    if (next === "raw") {
      setRaw(builderQuery);
      setRawError(null);
      setMode("raw");
      return;
    }
    const p = parseQuery(raw);
    if (!p) {
      setRawError("This query uses OR, grouping or wildcards the builder can't show as chips — keep editing it as raw text.");
      return;
    }
    setClauses(p.clauses);
    setFreeText(p.freeText);
    setRawError(null);
    setMode("builder");
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (mode === "raw") onSubmit(raw.trim());
    else {
      // A filled-in but not yet added chip is included in the search.
      const all = clauseIsComplete(draft) ? [...clauses, draft] : clauses;
      if (all !== clauses) {
        setClauses(all);
        setDraft((d) => ({ ...d, value: "" }));
      }
      onSubmit(serializeQuery(all, freeText));
    }
  };

  const def = fieldDef(draft.field);
  const draftOps = opsFor(draft.field);

  return (
    <form onSubmit={submit} className={clsx("rounded border border-line bg-surface shadow-card", className)} aria-label="Event query" data-testid="query-builder">
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
        <div role="tablist" aria-label="Query mode" className="inline-flex rounded border border-line-strong p-0.5">
          <button type="button" role="tab" aria-selected={mode === "builder"} onClick={() => switchMode("builder")} className={clsx("inline-flex items-center gap-1 rounded px-2 py-0.5 text-sm", mode === "builder" ? "bg-primary text-white" : "text-fg-muted hover:text-fg")}>
            <SlidersHorizontal size={12} aria-hidden /> Builder
          </button>
          <button type="button" role="tab" aria-selected={mode === "raw"} onClick={() => switchMode("raw")} className={clsx("inline-flex items-center gap-1 rounded px-2 py-0.5 text-sm", mode === "raw" ? "bg-primary text-white" : "text-fg-muted hover:text-fg")}>
            <Braces size={12} aria-hidden /> Raw query
          </button>
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          {actions}
          <Button type="submit" variant="primary" size="sm" icon={Search}>
            Search
          </Button>
        </div>
      </div>

      {mode === "builder" ? (
        <div className="space-y-2 px-3 py-2">
          <ul className="flex flex-wrap items-center gap-1.5" aria-label="Query conditions">
            {clauses.length === 0 ? <li className="text-sm text-fg-subtle">No conditions — add one below, or search free text.</li> : null}
            {clauses.map((c, i) => (
              <li key={`${c.field}-${i}`} className="inline-flex items-center gap-1 rounded-full border border-primary/30 bg-primary-soft py-0.5 pl-2 pr-0.5 text-sm" data-testid="query-chip">
                {i > 0 ? <span className="mr-0.5 text-2xs font-semibold text-fg-subtle">AND</span> : null}
                <span className="font-mono text-xs text-primary">{c.field}</span>
                <span className="text-fg-muted">{QUERY_OP_LABELS[c.op]}</span>
                {c.op !== "exists" ? <span className="max-w-[240px] truncate font-medium text-fg">{c.value}</span> : null}
                <IconButton icon={X} size={11} label={`Remove condition ${serializeClause(c)}`} className="h-5 w-5" onClick={() => setClauses((all) => all.filter((_, j) => j !== i))} />
              </li>
            ))}
          </ul>
          <div className="flex flex-wrap items-end gap-1.5">
            <label className="flex flex-col text-2xs text-fg-muted">
              Field
              <Input
                list={listId}
                value={draft.field}
                onChange={(e) => {
                  const field = e.target.value;
                  const ops = opsFor(field);
                  setDraft((d) => ({ ...d, field, op: ops.includes(d.op) ? d.op : ops[0]! }));
                }}
                className="h-7 w-52 font-mono text-xs"
                aria-label="Field"
                aria-invalid={draft.field !== "" && !isValidField(draft.field)}
              />
              <datalist id={listId}>
                {EVENT_FIELDS.map((f) => (
                  <option key={f.field} value={f.field}>
                    {f.label}
                  </option>
                ))}
              </datalist>
            </label>
            <label className="flex flex-col text-2xs text-fg-muted">
              Operator
              <Select value={draft.op} onChange={(e) => setDraft((d) => ({ ...d, op: e.target.value as QueryOp }))} className="h-7 w-32" aria-label="Operator">
                {draftOps.map((op) => (
                  <option key={op} value={op}>
                    {QUERY_OP_LABELS[op]}
                  </option>
                ))}
              </Select>
            </label>
            {draft.op !== "exists" ? (
              <label className="flex flex-col text-2xs text-fg-muted">
                Value
                {def?.options && draft.op !== "in" ? (
                  <Select value={draft.value} onChange={(e) => setDraft((d) => ({ ...d, value: e.target.value }))} className="h-7 w-44" aria-label="Value">
                    <option value="">Select…</option>
                    {def.options.map((o) => (
                      <option key={o} value={o}>
                        {o}
                      </option>
                    ))}
                  </Select>
                ) : (
                  <Input
                    value={draft.value}
                    onChange={(e) => setDraft((d) => ({ ...d, value: e.target.value }))}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && clauseIsComplete(draft) && !e.metaKey && !e.ctrlKey) {
                        e.preventDefault();
                        addDraft();
                      }
                    }}
                    placeholder={draft.op === "in" ? "a, b, c" : def?.type === "number" ? "number" : "value"}
                    inputMode={def?.type === "number" && draft.op !== "in" ? "decimal" : undefined}
                    className="h-7 w-44"
                    aria-label="Value"
                  />
                )}
              </label>
            ) : null}
            <Button size="sm" icon={Plus} onClick={addDraft} disabled={!clauseIsComplete(draft)}>
              Add condition
            </Button>
            <label className="ml-auto flex min-w-[220px] flex-1 flex-col text-2xs text-fg-muted">
              Free text
              <Input value={freeText} onChange={(e) => setFreeText(e.target.value)} placeholder={placeholder} className="h-7" aria-label="Free text" />
            </label>
          </div>
          <p className="truncate font-mono text-2xs text-fg-subtle" title={builderQuery} data-testid="query-preview">
            {builderQuery ? `Query: ${builderQuery}` : "Query: (all events in range)"}
          </p>
        </div>
      ) : (
        <div className="space-y-1 px-3 py-2">
          <Textarea
            value={raw}
            onChange={(e) => {
              setRaw(e.target.value);
              setRawError(null);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                onSubmit(raw.trim());
              }
            }}
            rows={2}
            spellCheck={false}
            className="font-mono text-xs"
            aria-label="Raw query"
            placeholder='process.name:powershell.exe AND network.dstPort:>=1024 AND NOT user.name:"svc backup"'
          />
          <p className="text-2xs text-fg-subtle">
            Syntax: <code>field:value</code>, <code>field:"a b"</code>, <code>field:*part*</code>, <code>field:&gt;=10</code>, <code>field:(a OR b)</code>, <code>field:*</code>, AND / OR / NOT. Ctrl+Enter runs the search.
          </p>
          {rawError ? (
            <p role="alert" className="text-xs text-sev-high">
              {rawError}
            </p>
          ) : null}
        </div>
      )}
    </form>
  );
}
