/**
 * Sigma condition grammar (Bloody's own recursive-descent implementation).
 *
 *   expr      := or
 *   or        := and ( "or" and )*
 *   and       := not ( "and" not )*
 *   not       := "not" not | primary
 *   primary   := "(" expr ")" | quantifier | IDENT
 *   quantifier:= ( NUMBER | "all" | "any" ) "of" ( PATTERN | "them" )
 *
 * Precedence: not > and > or. Keywords are case-insensitive. PATTERN may contain `*`
 * wildcards ("1 of selection_*"); `them` covers every selection not starting with "_".
 * Aggregation pipes (`| count() by …`) are rejected — use a threshold rule instead.
 */
export type ConditionNode =
  | { type: "and"; items: ConditionNode[] }
  | { type: "or"; items: ConditionNode[] }
  | { type: "not"; item: ConditionNode }
  | { type: "ref"; name: string }
  | { type: "quantifier"; quantity: "all" | number; names: string[]; pattern: string };

export class ConditionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConditionError";
  }
}

type Token = { kind: "lparen" | "rparen" | "word"; text: string; pos: number };

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < input.length) {
    const ch = input[i]!;
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (ch === "(") {
      tokens.push({ kind: "lparen", text: ch, pos: i++ });
      continue;
    }
    if (ch === ")") {
      tokens.push({ kind: "rparen", text: ch, pos: i++ });
      continue;
    }
    if (ch === "|") throw new ConditionError(`Aggregation expressions ("|" at position ${i}) are not supported in Sigma conditions; use a threshold rule`);
    const start = i;
    while (i < input.length && !/[\s()|]/.test(input[i]!)) i++;
    const text = input.slice(start, i);
    if (!/^[A-Za-z0-9_*?.\-]+$/.test(text)) throw new ConditionError(`Invalid token "${text}" at position ${start}`);
    tokens.push({ kind: "word", text, pos: start });
  }
  return tokens;
}

const KEYWORDS = new Set(["and", "or", "not", "of", "them", "all", "any"]);

/** Parse a condition and resolve references/patterns against the available selection names. */
export function parseCondition(condition: string, selectionNames: readonly string[]): ConditionNode {
  const tokens = tokenize(condition);
  if (tokens.length === 0) throw new ConditionError("Condition is empty");
  let pos = 0;
  const peek = () => tokens[pos];
  const isWord = (t: Token | undefined, w: string) => t?.kind === "word" && t.text.toLowerCase() === w;

  const parseOr = (): ConditionNode => {
    const items = [parseAnd()];
    while (isWord(peek(), "or")) {
      pos++;
      items.push(parseAnd());
    }
    return items.length === 1 ? items[0]! : { type: "or", items };
  };
  const parseAnd = (): ConditionNode => {
    const items = [parseNot()];
    while (isWord(peek(), "and")) {
      pos++;
      items.push(parseNot());
    }
    return items.length === 1 ? items[0]! : { type: "and", items };
  };
  const parseNot = (): ConditionNode => {
    if (isWord(peek(), "not")) {
      pos++;
      return { type: "not", item: parseNot() };
    }
    return parsePrimary();
  };
  const parsePrimary = (): ConditionNode => {
    const t = peek();
    if (!t) throw new ConditionError("Unexpected end of condition");
    if (t.kind === "lparen") {
      pos++;
      const inner = parseOr();
      if (peek()?.kind !== "rparen") throw new ConditionError(`Missing ")" for "(" at position ${t.pos}`);
      pos++;
      return inner;
    }
    if (t.kind === "rparen") throw new ConditionError(`Unexpected ")" at position ${t.pos}`);
    const lower = t.text.toLowerCase();
    const next = tokens[pos + 1];
    if ((lower === "all" || lower === "any" || /^\d+$/.test(lower)) && isWord(next, "of")) {
      pos += 2;
      const target = peek();
      if (!target || target.kind !== "word") throw new ConditionError(`Expected a selection pattern or "them" after "${t.text} of"`);
      pos++;
      const quantity = lower === "all" ? "all" : lower === "any" ? 1 : Number(lower);
      if (quantity === 0) throw new ConditionError(`"0 of" is not a meaningful quantifier`);
      const pattern = target.text;
      const names = isWord(target, "them") ? selectionNames.filter((n) => !n.startsWith("_")) : selectionNames.filter((n) => globMatch(pattern, n));
      if (names.length === 0) throw new ConditionError(`Pattern "${pattern}" matches no selection`);
      if (typeof quantity === "number" && quantity > names.length) throw new ConditionError(`"${quantity} of ${pattern}" requires more selections than the ${names.length} defined`);
      return { type: "quantifier", quantity, names, pattern };
    }
    if (KEYWORDS.has(lower)) throw new ConditionError(`Unexpected keyword "${t.text}" at position ${t.pos}`);
    if (/[*?]/.test(t.text)) throw new ConditionError(`Wildcard "${t.text}" is only valid after "1 of" / "all of"`);
    if (!selectionNames.includes(t.text)) throw new ConditionError(`Condition references unknown selection "${t.text}"`);
    pos++;
    return { type: "ref", name: t.text };
  };

  const node = parseOr();
  if (pos < tokens.length) throw new ConditionError(`Unexpected "${tokens[pos]!.text}" at position ${tokens[pos]!.pos}`);
  return node;
}

/** Evaluate a parsed condition given a (memoized) selection evaluator. */
export function evaluateCondition(node: ConditionNode, selection: (name: string) => boolean): boolean {
  switch (node.type) {
    case "ref":
      return selection(node.name);
    case "not":
      return !evaluateCondition(node.item, selection);
    case "and":
      return node.items.every((n) => evaluateCondition(n, selection));
    case "or":
      return node.items.some((n) => evaluateCondition(n, selection));
    case "quantifier": {
      if (node.quantity === "all") return node.names.every(selection);
      let hits = 0;
      for (const n of node.names) {
        if (selection(n) && ++hits >= (node.quantity as number)) return true;
      }
      return false;
    }
  }
}

/** Selection names referenced anywhere in the condition. */
export function referencedSelections(node: ConditionNode, out = new Set<string>()): Set<string> {
  switch (node.type) {
    case "ref":
      out.add(node.name);
      break;
    case "not":
      referencedSelections(node.item, out);
      break;
    case "and":
    case "or":
      node.items.forEach((n) => referencedSelections(n, out));
      break;
    case "quantifier":
      node.names.forEach((n) => out.add(n));
      break;
  }
  return out;
}

function globMatch(pattern: string, name: string): boolean {
  const re = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\-]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`);
  return re.test(name);
}
