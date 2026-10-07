/**
 * Safe dotted-path access ("incident.assets.0.name") used by conditions and templates.
 * Only own, enumerable properties are visited and prototype-related keys are refused, so a
 * user-authored template or condition can never reach `__proto__`, `constructor` or getters
 * on the prototype chain.
 */
const FORBIDDEN_SEGMENTS = new Set(["__proto__", "prototype", "constructor"]);
const SEGMENT_RE = /^[A-Za-z0-9_$-]{1,128}$/;

export function isValidPath(path: string): boolean {
  if (path.length === 0 || path.length > 512) return false;
  return path.split(".").every((seg) => SEGMENT_RE.test(seg) && !FORBIDDEN_SEGMENTS.has(seg));
}

export function getPath(root: unknown, path: string): unknown {
  if (!isValidPath(path)) return undefined;
  let cur: unknown = root;
  for (const seg of path.split(".")) {
    if (cur === null || cur === undefined) return undefined;
    if (Array.isArray(cur)) {
      if (!/^\d+$/.test(seg)) {
        if (seg === "length") {
          cur = cur.length;
          continue;
        }
        return undefined;
      }
      cur = cur[Number(seg)];
      continue;
    }
    if (typeof cur !== "object") return undefined;
    if (cur instanceof Date) return undefined;
    if (!Object.prototype.hasOwnProperty.call(cur, seg)) return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}
