/**
 * Minimal, non-validating XML parser for engine reports (Greenbone GMP, OpenVAS exports).
 *
 * Security posture: DOCTYPE declarations are rejected outright — no DTDs, no entity
 * expansion, no external entities (XXE / billion-laughs are impossible by construction).
 * Only the five predefined entities and numeric character references are decoded.
 * Depth and node count are bounded. Namespaces are kept as part of the element name.
 */

export interface XmlElement {
  name: string;
  attrs: Record<string, string>;
  children: XmlElement[];
  /** Concatenated direct text content (including CDATA), entity-decoded, untrimmed. */
  text: string;
}

export class XmlParseError extends Error {
  constructor(message: string, readonly position: number) {
    super(`${message} at offset ${position}`);
    this.name = "XmlParseError";
  }
}

export interface XmlParseOptions {
  maxDepth?: number;
  maxNodes?: number;
}

const NAMED: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

export function decodeEntities(s: string): string {
  if (!s.includes("&")) return s;
  return s.replace(/&(#x[0-9a-fA-F]{1,6}|#[0-9]{1,7}|lt|gt|amp|quot|apos);/g, (m, ent: string) => {
    if (ent.startsWith("#x")) {
      const cp = Number.parseInt(ent.slice(2), 16);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    }
    if (ent.startsWith("#")) {
      const cp = Number.parseInt(ent.slice(1), 10);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    }
    return NAMED[ent] ?? m;
  });
}

const NAME_RE = /^[A-Za-z_][\w.:-]*/;
const ATTR_RE = /([A-Za-z_][\w.:-]*)\s*=\s*("([^"]*)"|'([^']*)')/g;

export function parseXml(input: string, opts: XmlParseOptions = {}): XmlElement {
  const maxDepth = opts.maxDepth ?? 64;
  const maxNodes = opts.maxNodes ?? 2_000_000;
  const root: XmlElement = { name: "#document", attrs: {}, children: [], text: "" };
  const stack: XmlElement[] = [root];
  let nodes = 0;
  let i = 0;
  const n = input.length;

  while (i < n) {
    const lt = input.indexOf("<", i);
    const textEnd = lt === -1 ? n : lt;
    if (textEnd > i) {
      const top = stack[stack.length - 1];
      if (top && top !== root) top.text += decodeEntities(input.slice(i, textEnd));
    }
    if (lt === -1) break;
    i = lt;

    if (input.startsWith("<?", i)) {
      const end = input.indexOf("?>", i + 2);
      if (end === -1) throw new XmlParseError("unterminated processing instruction", i);
      i = end + 2;
      continue;
    }
    if (input.startsWith("<!--", i)) {
      const end = input.indexOf("-->", i + 4);
      if (end === -1) throw new XmlParseError("unterminated comment", i);
      i = end + 3;
      continue;
    }
    if (input.startsWith("<![CDATA[", i)) {
      const end = input.indexOf("]]>", i + 9);
      if (end === -1) throw new XmlParseError("unterminated CDATA section", i);
      const top = stack[stack.length - 1];
      if (top && top !== root) top.text += input.slice(i + 9, end);
      i = end + 3;
      continue;
    }
    if (input.startsWith("<!", i)) {
      // <!DOCTYPE …> and any other markup declaration: refused (XXE / entity expansion).
      throw new XmlParseError("markup declarations (DOCTYPE/ENTITY) are not allowed", i);
    }
    if (input.startsWith("</", i)) {
      const end = input.indexOf(">", i + 2);
      if (end === -1) throw new XmlParseError("unterminated closing tag", i);
      const name = input.slice(i + 2, end).trim();
      const top = stack.pop();
      if (!top || top === root || top.name !== name) throw new XmlParseError(`mismatched closing tag </${name}>`, i);
      i = end + 1;
      continue;
    }

    // start tag — find the closing ">" outside quoted attribute values
    let j = i + 1;
    let quote: string | null = null;
    while (j < n) {
      const c = input[j];
      if (quote) {
        if (c === quote) quote = null;
      } else if (c === '"' || c === "'") quote = c;
      else if (c === ">") break;
      j++;
    }
    if (j >= n) throw new XmlParseError("unterminated start tag", i);
    let body = input.slice(i + 1, j);
    const selfClosing = body.endsWith("/");
    if (selfClosing) body = body.slice(0, -1);
    const nameMatch = NAME_RE.exec(body);
    if (!nameMatch) throw new XmlParseError("invalid element name", i);
    const el: XmlElement = { name: nameMatch[0], attrs: {}, children: [], text: "" };
    const attrPart = body.slice(nameMatch[0].length);
    for (const m of attrPart.matchAll(ATTR_RE)) {
      const key = m[1];
      if (key) el.attrs[key] = decodeEntities(m[3] ?? m[4] ?? "");
    }
    if (++nodes > maxNodes) throw new XmlParseError("document has too many elements", i);
    const parent = stack[stack.length - 1];
    if (!parent) throw new XmlParseError("invalid document structure", i);
    parent.children.push(el);
    if (!selfClosing) {
      if (stack.length > maxDepth) throw new XmlParseError("document nesting too deep", i);
      stack.push(el);
    }
    i = j + 1;
  }
  if (stack.length !== 1) throw new XmlParseError(`unclosed element <${stack[stack.length - 1]?.name ?? "?"}>`, n);
  const docEl = root.children[0];
  if (!docEl || root.children.length !== 1) throw new XmlParseError("document must have exactly one root element", 0);
  return docEl;
}

export function xmlChild(el: XmlElement | undefined, name: string): XmlElement | undefined {
  return el?.children.find((c) => c.name === name);
}

export function xmlChildren(el: XmlElement | undefined, name: string): XmlElement[] {
  return el ? el.children.filter((c) => c.name === name) : [];
}

/** Trimmed text at a "a/b/c" child path; undefined when absent or empty. */
export function xmlText(el: XmlElement | undefined, path?: string): string | undefined {
  let cur = el;
  if (path) for (const part of path.split("/")) cur = xmlChild(cur, part);
  const t = cur?.text.trim();
  return t ? t : undefined;
}

/** All descendants with a given name (depth-first, document order). */
export function xmlDescendants(el: XmlElement, name: string, out: XmlElement[] = []): XmlElement[] {
  for (const c of el.children) {
    if (c.name === name) out.push(c);
    xmlDescendants(c, name, out);
  }
  return out;
}
