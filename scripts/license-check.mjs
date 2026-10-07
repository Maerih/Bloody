#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
// Copyright (c) 2026 Bloody. All rights reserved.
/**
 * Bloody dependency licence gate.
 *
 * Walks the installed npm dependency graph of every workspace project and fails when a package
 * whose licence is incompatible with a proprietary SaaS product is linked into it:
 *
 *   denied   GPL / AGPL / LGPL (any version), SSPL, Business Source (BUSL / "BSL-1.1"),
 *            Elastic License 2.0 (ELv2), Commons Clause, RSAL, PolyForm, share-alike / NC
 *            Creative Commons, other strong / network copyleft
 *   review   weak (file-level) copyleft such as MPL / EPL / CDDL — must be allowlisted
 *   unknown  no licence metadata, "SEE LICENSE IN", UNLICENSED third-party code, unparseable
 *
 * SPDX expressions are evaluated properly: `A OR B` passes when any alternative is acceptable
 * (dual licences — the permissive option is recorded as the one we use), `A AND B` needs all.
 * Exceptions live in scripts/license-allowlist.json; each entry is pinned to the declared licence
 * string, needs a justification and an approver, may expire, and denied licences additionally
 * need an `exceptionRef` (legal sign-off / ADR). Stale or unused entries are reported.
 *
 * Sources:
 *   --source fs    (default) resolve the graph from each workspace's package.json through
 *                  node_modules (Node resolution, works with pnpm's isolated layout), classify
 *                  packages as prod (reachable from `dependencies`/`optionalDependencies`/
 *                  `peerDependencies`) or dev (reachable only from `devDependencies`).
 *   --source pnpm  use `pnpm licenses list --json [--prod]`.
 *
 * Usage:
 *   node scripts/license-check.mjs [--source fs|pnpm] [--prod] [--full] [--quiet]
 *        [--allowlist <file>] [--json <file>] [--markdown <file>] [--cyclonedx <file>]
 *
 * Exit codes: 0 = compliant, 1 = violations, 2 = usage / internal error.
 * Pure Node.js (>= 20), no dependencies.
 */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
/** Repository to inspect; overridable for fixture tests (scripts/license-check.test.mjs). */
const REPO_ROOT = resolve(process.env.BLOODY_LICENSE_CHECK_ROOT ?? resolve(SCRIPT_DIR, ".."));
const TOOL = { name: "bloody-license-check", version: "1.0.0" };

// ─── Policy ────────────────────────────────────────────────────────────────────────────────

/** Licence classes, ordered from best to worst. */
const CLASS = /** @type {const} */ ({
  permissive: 0,
  attribution: 1, // permissive content licences with attribution duties (CC-BY): fine for build tooling
  review: 2, // weak copyleft — allowed only through an allowlist entry
  denied: 3,
  unknown: 4,
});

const PERMISSIVE = new Set([
  "MIT", "MIT-0", "MIT-CMU", "X11", "ISC", "0BSD", "BSD-1-Clause", "BSD-2-Clause", "BSD-2-Clause-Patent",
  "BSD-3-Clause", "BSD-3-Clause-Clear", "BSD-4-Clause-UC", "Apache-2.0", "Apache-1.1", "Zlib", "zlib-acknowledgement",
  "Unlicense", "CC0-1.0", "BlueOak-1.0.0", "Python-2.0", "PSF-2.0", "PostgreSQL", "BSL-1.0" /* Boost, not Business Source */,
  "Unicode-DFS-2016", "Unicode-3.0", "W3C", "W3C-20150513", "NCSA", "UPL-1.0", "ICU", "OFL-1.1", "curl", "WTFPL",
  "AFL-2.1", "AFL-3.0", "MS-PL", "Beerware", "HPND", "libpng-2.0", "BSD-Source-Code", "Info-ZIP", "Ruby",
]);
const ATTRIBUTION = new Set(["CC-BY-3.0", "CC-BY-4.0", "CC-BY-2.0", "CC-BY-2.5"]);
const REVIEW = new Set([
  "MPL-1.0", "MPL-1.1", "MPL-2.0", "MPL-2.0-no-copyleft-exception", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1",
  "CPL-1.0", "MS-RL", "Artistic-1.0", "Artistic-2.0", "APSL-2.0", "ErlPL-1.1", "IPL-1.0", "LPPL-1.3c",
]);
/** Prefix / exact patterns for denied licences (matched on the normalized SPDX id). */
const DENIED = [
  /^A?GPL-/i, /^LGPL-/i, /^GPL$/i, /^AGPL$/i, /^LGPL$/i, /^SSPL/i, /^BUSL-/i, /^BSL-1\.1$/i /* Business Source, mis-tagged */,
  /^Elastic-/i, /^ELv2$/i, /^Commons-Clause$/i, /^RSAL/i, /^Redis-Source-Available/i, /^PolyForm-/i,
  /^CC-BY-(.*-)?(SA|NC|ND)-/i, /^OSL-/i, /^EUPL-/i, /^CPAL-/i, /^RPL-/i, /^Sleepycat$/i, /^SISSL/i, /^JSON$/i,
  /^Confluent-Community/i, /^Parity-/i, /^QPL-/i, /^Watcom-/i, /^LicenseRef-.*(Proprietary|Commercial)/i,
];

/** Common non-SPDX spellings → SPDX ids. Keys are lower-cased and whitespace-collapsed. */
const ALIASES = new Map([
  ["mit license", "MIT"], ["the mit license", "MIT"], ["mit*", "MIT"], ["expat", "MIT"], ["mit/x11", "MIT"],
  ["apache 2.0", "Apache-2.0"], ["apache-2", "Apache-2.0"], ["apache 2", "Apache-2.0"], ["apache license 2.0", "Apache-2.0"],
  ["apache license, version 2.0", "Apache-2.0"], ["apache2", "Apache-2.0"], ["apache-2.0*", "Apache-2.0"],
  ["isc license", "ISC"], ["bsd-3", "BSD-3-Clause"], ["bsd 3-clause", "BSD-3-Clause"], ["new bsd", "BSD-3-Clause"],
  ["bsd-2", "BSD-2-Clause"], ["bsd 2-clause", "BSD-2-Clause"], ["simplified bsd", "BSD-2-Clause"], ["freebsd", "BSD-2-Clause"],
  ["public domain", "Unlicense"], ["cc0", "CC0-1.0"], ["wtfpl", "WTFPL"], ["python-2.0", "Python-2.0"],
  ["mpl 2.0", "MPL-2.0"], ["mpl-2", "MPL-2.0"], ["eplv2", "EPL-2.0"],
  ["gpl", "GPL"], ["gplv2", "GPL-2.0-only"], ["gplv3", "GPL-3.0-only"], ["lgpl", "LGPL"], ["agpl", "AGPL"], ["agplv3", "AGPL-3.0-only"],
  ["sspl", "SSPL-1.0"], ["server side public license", "SSPL-1.0"], ["elv2", "Elastic-2.0"], ["elastic license 2.0", "Elastic-2.0"],
  ["busl", "BUSL-1.1"], ["business source license", "BUSL-1.1"], ["business source license 1.1", "BUSL-1.1"],
]);

// ─── CLI ───────────────────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const opts = { source: "fs", prod: false, full: false, quiet: false, allowlist: null, json: null, markdown: null, cyclonedx: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) throw new UsageError(`${a} needs a value`);
      return v;
    };
    switch (a) {
      case "--source": opts.source = next(); break;
      case "--prod": opts.prod = true; break;
      case "--full": opts.full = true; break;
      case "--quiet": opts.quiet = true; break;
      case "--allowlist": opts.allowlist = resolve(next()); break;
      case "--json": opts.json = resolve(next()); break;
      case "--markdown": opts.markdown = resolve(next()); break;
      case "--cyclonedx": opts.cyclonedx = resolve(next()); break;
      case "-h": case "--help": opts.help = true; break;
      default: throw new UsageError(`unknown argument ${a}`);
    }
  }
  if (!["fs", "pnpm"].includes(opts.source)) throw new UsageError(`--source must be fs or pnpm`);
  return opts;
}

class UsageError extends Error {}

// ─── SPDX expression evaluation ───────────────────────────────────────────────────────────

function normalizeId(raw) {
  let id = raw.trim().replace(/^\(+|\)+$/g, "");
  const alias = ALIASES.get(id.toLowerCase().replace(/\s+/g, " "));
  if (alias) return alias;
  id = id.replace(/\+$/, ""); // "GPL-2.0+" → GPL-2.0 (still denied); "-or-later" is part of the id
  return id;
}

function classifyId(id) {
  if (!id) return "unknown";
  if (PERMISSIVE.has(id)) return "permissive";
  if (ATTRIBUTION.has(id)) return "attribution";
  if (REVIEW.has(id)) return "review";
  if (DENIED.some((re) => re.test(id))) return "denied";
  return "unknown";
}

/** Tokenize an SPDX-ish expression. Accepts lowercase operators and "/" or "," as OR (seen in the wild). */
function tokenize(expr) {
  const tokens = [];
  const re = /\s*(\(|\)|\bAND\b|\bOR\b|\bWITH\b|\band\b|\bor\b|\bwith\b|\/|,|[^\s()/,]+(?:\s+(?!AND\b|OR\b|WITH\b|and\b|or\b|with\b)[^\s()/,]+)*)\s*/gy;
  let m;
  let last = 0;
  while ((m = re.exec(expr)) !== null) {
    if (m[0].length === 0) break;
    last = re.lastIndex;
    const t = m[1];
    const up = t.toUpperCase();
    if (t === "(" || t === ")") tokens.push({ kind: t });
    else if (up === "AND") tokens.push({ kind: "AND" });
    else if (up === "OR" || t === "/" || t === ",") tokens.push({ kind: "OR" });
    else if (up === "WITH") tokens.push({ kind: "WITH" });
    else tokens.push({ kind: "ID", value: t });
  }
  if (last !== expr.length && expr.slice(last).trim() !== "") throw new Error(`cannot parse licence expression "${expr}"`);
  return tokens;
}

/** Recursive-descent parser: or := and (OR and)* ; and := atom (AND atom)* ; atom := ID [WITH ID] | ( or ) */
function parseExpression(expr) {
  const tokens = tokenize(expr);
  let pos = 0;
  const peek = () => tokens[pos];
  const parseOr = () => {
    const parts = [parseAnd()];
    while (peek()?.kind === "OR") { pos++; parts.push(parseAnd()); }
    return parts.length === 1 ? parts[0] : { op: "OR", parts };
  };
  const parseAnd = () => {
    const parts = [parseAtom()];
    while (peek()?.kind === "AND") { pos++; parts.push(parseAtom()); }
    return parts.length === 1 ? parts[0] : { op: "AND", parts };
  };
  const parseAtom = () => {
    const t = tokens[pos++];
    if (!t) throw new Error(`unexpected end of licence expression "${expr}"`);
    if (t.kind === "(") {
      const inner = parseOr();
      if (tokens[pos++]?.kind !== ")") throw new Error(`unbalanced parentheses in "${expr}"`);
      return inner;
    }
    if (t.kind !== "ID") throw new Error(`unexpected "${t.kind}" in "${expr}"`);
    const node = { id: normalizeId(t.value) };
    if (peek()?.kind === "WITH") {
      pos++;
      const ex = tokens[pos++];
      if (ex?.kind !== "ID") throw new Error(`WITH needs an exception id in "${expr}"`);
      node.exception = ex.value;
    }
    return node;
  };
  const tree = parseOr();
  if (pos !== tokens.length) throw new Error(`trailing tokens in licence expression "${expr}"`);
  return tree;
}

/**
 * Evaluate a parsed expression. Returns the effective class and the licence ids we rely on
 * (for OR: the best alternative; for AND: all operands).
 */
function evaluate(node) {
  if ("id" in node) {
    return { cls: classifyId(node.id), chosen: [node.exception ? `${node.id} WITH ${node.exception}` : node.id] };
  }
  const results = node.parts.map(evaluate);
  if (node.op === "OR") {
    return results.reduce((best, r) => (CLASS[r.cls] < CLASS[best.cls] ? r : best));
  }
  const worst = results.reduce((w, r) => (CLASS[r.cls] > CLASS[w.cls] ? r : w));
  return { cls: worst.cls, chosen: results.flatMap((r) => r.chosen) };
}

function assessLicense(declared) {
  if (!declared || typeof declared !== "string" || declared.trim() === "") return { cls: "unknown", chosen: [], note: "no licence metadata" };
  const d = declared.trim();
  if (/^UNLICENSED$/i.test(d)) return { cls: "unknown", chosen: [], note: "third-party package declares UNLICENSED (proprietary)" };
  if (/^SEE LICEN[CS]E IN/i.test(d)) return { cls: "unknown", chosen: [], note: `custom licence (${d})` };
  if (/^unknown$/i.test(d)) return { cls: "unknown", chosen: [], note: "licence could not be determined" };
  try {
    const tree = parseExpression(d);
    const r = evaluate(tree);
    const dual = "op" in tree && tree.op === "OR";
    return { ...r, note: dual && r.cls === "permissive" ? `multi-licensed; used under ${r.chosen.join(" AND ")}` : undefined };
  } catch (err) {
    return { cls: "unknown", chosen: [], note: err instanceof Error ? err.message : String(err) };
  }
}

// ─── Licence text sniffing (packages without a `license` field) ──────────────────────────

const TEXT_SIGNATURES = [
  [/GNU AFFERO GENERAL PUBLIC LICENSE/i, "AGPL-3.0-only"],
  [/GNU LESSER GENERAL PUBLIC LICENSE/i, "LGPL-3.0-only"],
  [/GNU GENERAL PUBLIC LICENSE/i, "GPL-3.0-only"],
  [/Server Side Public License/i, "SSPL-1.0"],
  [/Business Source License/i, "BUSL-1.1"],
  [/Elastic License 2\.0/i, "Elastic-2.0"],
  [/Mozilla Public License,? (Version|v\.?) ?2\.0/i, "MPL-2.0"],
  [/Apache License,?\s+Version 2\.0/i, "Apache-2.0"],
  [/Permission is hereby granted, free of charge, to any person obtaining a copy/i, "MIT"],
  [/Permission to use, copy, modify, and\/or distribute this software for any\s+purpose with or without fee is hereby granted/i, "ISC"],
  [/Redistribution and use in source and binary forms[\s\S]*Neither the name/i, "BSD-3-Clause"],
  [/Redistribution and use in source and binary forms/i, "BSD-2-Clause"],
  [/This is free and unencumbered software released into the public domain/i, "Unlicense"],
];

function sniffLicenseFile(dir) {
  let files;
  try {
    files = readdirSync(dir).filter((f) => /^(licen[cs]e|copying|copyright)(\.|-|$)/i.test(f));
  } catch {
    return null;
  }
  for (const f of files) {
    let text;
    try {
      text = readFileSync(join(dir, f), "utf8").slice(0, 20000);
    } catch {
      continue;
    }
    for (const [re, id] of TEXT_SIGNATURES) if (re.test(text)) return { id, file: f };
  }
  return null;
}

function declaredLicense(pkg) {
  if (typeof pkg.license === "string") return pkg.license;
  if (pkg.license && typeof pkg.license === "object" && typeof pkg.license.type === "string") return pkg.license.type;
  if (Array.isArray(pkg.licenses) && pkg.licenses.length > 0) {
    const ids = pkg.licenses.map((l) => (typeof l === "string" ? l : l?.type)).filter((x) => typeof x === "string");
    if (ids.length > 0) return ids.length === 1 ? ids[0] : `(${ids.join(" OR ")})`;
  }
  return null;
}

// ─── Workspace discovery ──────────────────────────────────────────────────────────────────

function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

/** Read pnpm-workspace.yaml `packages:` globs (only `dir/*` and literal dirs are needed here). */
function workspaceDirs(root) {
  const dirs = [root];
  const wsFile = join(root, "pnpm-workspace.yaml");
  if (!existsSync(wsFile)) return dirs;
  const lines = readFileSync(wsFile, "utf8").split(/\r?\n/);
  let inPackages = false;
  for (const line of lines) {
    if (/^packages\s*:/.test(line)) { inPackages = true; continue; }
    if (inPackages && /^\S/.test(line)) inPackages = false;
    if (!inPackages) continue;
    const m = /^\s*-\s*["']?([^"'#]+?)["']?\s*(#.*)?$/.exec(line);
    if (!m) continue;
    const pattern = m[1].trim();
    if (pattern.startsWith("!")) continue;
    if (pattern.endsWith("/*")) {
      const base = join(root, pattern.slice(0, -2));
      if (!existsSync(base)) continue;
      for (const d of readdirSync(base)) {
        const p = join(base, d);
        if (statSync(p).isDirectory() && existsSync(join(p, "package.json"))) dirs.push(p);
      }
    } else if (!pattern.includes("*")) {
      const p = join(root, pattern);
      if (existsSync(join(p, "package.json"))) dirs.push(p);
    } else {
      throw new Error(`unsupported workspace glob "${pattern}" in pnpm-workspace.yaml`);
    }
  }
  return dirs;
}

// ─── Source: filesystem graph walk ────────────────────────────────────────────────────────

function resolvePackageDir(name, fromDir) {
  let dir = fromDir;
  for (;;) {
    const candidate = join(dir, "node_modules", name, "package.json");
    if (existsSync(candidate)) return realpathSync(dirname(candidate));
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function collectFromFs(root) {
  const workspaces = workspaceDirs(root).map((dir) => ({ dir: realpathSync(dir), pkg: readJson(join(dir, "package.json")) }));
  const workspaceRealDirs = new Set(workspaces.map((w) => w.dir));
  /** @type {Map<string, any>} realpath → package record */
  const packages = new Map();
  const edges = new Map(); // realpath → Set(realpath)
  const warnings = [];

  const isWorkspace = (real) => workspaceRealDirs.has(real) || !real.split(sep).includes("node_modules");

  const visit = (roots, scope) => {
    const queue = [...roots];
    while (queue.length > 0) {
      const { name, fromDir, chain, optional, parentKey } = queue.shift();
      const real = resolvePackageDir(name, fromDir);
      if (!real) {
        if (!optional) warnings.push(`unresolved dependency ${name} (required by ${chain.join(" > ")})`);
        continue;
      }
      if (isWorkspace(real)) continue; // workspace projects are roots themselves
      if (parentKey) {
        if (!edges.has(parentKey)) edges.set(parentKey, new Set());
        edges.get(parentKey).add(real);
      }
      const existing = packages.get(real);
      if (existing) {
        // Already seen: only a dev → prod upgrade needs another expansion of its subtree.
        if (scope !== "prod" || existing.scope === "prod") continue;
        existing.scope = "prod";
        existing.chain = [...chain, `${existing.name}@${existing.version}`];
      }
      let pkg;
      try {
        pkg = readJson(join(real, "package.json"));
      } catch (err) {
        warnings.push(`cannot read ${join(real, "package.json")}: ${err.message}`);
        continue;
      }
      const record = existing ?? {
        name: pkg.name ?? name,
        version: pkg.version ?? "0.0.0",
        declared: declaredLicense(pkg),
        inferredFrom: null,
        scope,
        chain: [...chain, `${pkg.name ?? name}@${pkg.version ?? "?"}`],
        dir: real,
        homepage: typeof pkg.homepage === "string" ? pkg.homepage : null,
      };
      if (!existing) {
        if (!record.declared || /^SEE LICEN[CS]E IN/i.test(record.declared)) {
          const sniff = sniffLicenseFile(real);
          if (sniff) {
            record.inferredFrom = sniff.file;
            record.declaredRaw = record.declared;
            record.declared = sniff.id;
          }
        }
        packages.set(real, record);
      }
      const next = [
        ...Object.keys(pkg.dependencies ?? {}).map((n) => ({ n, optional: false })),
        ...Object.keys(pkg.optionalDependencies ?? {}).map((n) => ({ n, optional: true })),
        ...Object.keys(pkg.peerDependencies ?? {}).map((n) => ({ n, optional: true })),
      ];
      for (const { n, optional: opt } of next) {
        queue.push({ name: n, fromDir: real, chain: record.chain, optional: opt, parentKey: real });
      }
    }
  };

  const rootsFor = (kind) =>
    workspaces.flatMap((w) => {
      const label = relative(root, w.dir) || ".";
      const fields = kind === "prod" ? ["dependencies", "optionalDependencies", "peerDependencies"] : ["devDependencies"];
      return fields.flatMap((f) =>
        Object.keys(w.pkg[f] ?? {}).map((name) => ({
          name,
          fromDir: w.dir,
          chain: [label],
          optional: f !== "dependencies" && f !== "devDependencies",
          parentKey: `workspace:${label}`,
        })),
      );
    });

  visit(rootsFor("prod"), "prod");
  visit(rootsFor("dev"), "dev");
  return { packages: [...packages.values()], edges, warnings, workspaces };
}

// ─── Source: pnpm licenses list ──────────────────────────────────────────────────────────

function pnpmLicenses(root, prod) {
  const args = ["licenses", "list", "--json", ...(prod ? ["--prod"] : [])];
  const out = execFileSync("pnpm", args, { cwd: root, encoding: "utf8", maxBuffer: 256 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
  const parsed = JSON.parse(out || "{}");
  const result = [];
  for (const [license, list] of Object.entries(parsed)) {
    for (const p of list) {
      for (const [i, version] of (p.versions ?? []).entries()) {
        result.push({ name: p.name, version, declared: license === "Unknown" ? null : (p.license ?? license), dir: p.paths?.[i] ?? p.paths?.[0] ?? null, homepage: p.homepage ?? null });
      }
    }
  }
  return result;
}

function collectFromPnpm(root) {
  const prod = pnpmLicenses(root, true);
  const all = pnpmLicenses(root, false);
  const prodKeys = new Set(prod.map((p) => `${p.name}@${p.version}`));
  const packages = all.map((p) => ({ ...p, scope: prodKeys.has(`${p.name}@${p.version}`) ? "prod" : "dev", chain: [], inferredFrom: null }));
  return { packages, edges: new Map(), warnings: [], workspaces: [] };
}

// ─── Allowlist ────────────────────────────────────────────────────────────────────────────

function loadAllowlist(file) {
  if (!existsSync(file)) return { entries: [], errors: [] };
  const raw = readJson(file);
  const entries = Array.isArray(raw.entries) ? raw.entries : [];
  const errors = [];
  entries.forEach((e, i) => {
    const where = `allowlist entry #${i + 1} (${e?.package ?? "?"})`;
    for (const field of ["package", "license", "justification", "approvedBy"]) {
      if (typeof e?.[field] !== "string" || e[field].trim() === "") errors.push(`${where}: "${field}" is required`);
    }
    if (typeof e?.justification === "string" && e.justification.trim().length < 20) errors.push(`${where}: justification must explain the decision (≥ 20 chars)`);
    if (e?.scope !== undefined && !["prod", "dev", "any"].includes(e.scope)) errors.push(`${where}: scope must be prod | dev | any`);
    if (e?.expires !== undefined && Number.isNaN(Date.parse(e.expires))) errors.push(`${where}: expires must be an ISO date`);
    e._used = false;
    e._index = i + 1;
  });
  return { entries, errors };
}

function versionMatches(spec, version) {
  if (spec === undefined || spec === "*") return true;
  if (Array.isArray(spec)) return spec.includes(version);
  return spec === version;
}

function findAllowlistEntry(entries, pkg) {
  return entries.find(
    (e) =>
      e.package === pkg.name &&
      versionMatches(e.versions, pkg.version) &&
      (e.scope ?? "any") !== (pkg.scope === "prod" ? "dev" : "prod") &&
      (e.license ?? "").trim() === (pkg.declared ?? "").trim(),
  );
}

// ─── Evaluation ───────────────────────────────────────────────────────────────────────────

function evaluatePackages(packages, allowlist, now) {
  const findings = [];
  for (const p of packages) {
    const a = assessLicense(p.declared);
    p.cls = a.cls;
    p.chosen = a.chosen;
    p.note = a.note ?? (p.inferredFrom ? `licence inferred from ${p.inferredFrom}` : undefined);
    // Attribution-only content licences are fine for build tooling, but anything shipped needs review.
    const effective = a.cls === "attribution" && p.scope === "prod" ? "review" : a.cls;
    if (effective === "permissive" || effective === "attribution") {
      p.verdict = "allowed";
      if (p.inferredFrom || a.cls === "attribution" || (p.note && p.note.startsWith("multi-licensed"))) findings.push(p);
      continue;
    }
    const entry = findAllowlistEntry(allowlist.entries, p);
    const stale = allowlist.entries.find((e) => e.package === p.name && versionMatches(e.versions, p.version) && e !== entry);
    if (entry) {
      entry._used = true;
      if (entry.expires && Date.parse(entry.expires) < now.getTime()) {
        p.verdict = "violation";
        p.note = `allowlist entry #${entry._index} expired on ${entry.expires}`;
      } else if (effective === "denied" && !(typeof entry.exceptionRef === "string" && entry.exceptionRef.trim())) {
        p.verdict = "violation";
        p.note = `denied licence; allowlist entry #${entry._index} lacks an exceptionRef (legal sign-off)`;
      } else {
        p.verdict = "allowlisted";
        p.note = `${entry.justification} (approved by ${entry.approvedBy}${entry.exceptionRef ? `, ${entry.exceptionRef}` : ""})`;
      }
    } else {
      p.verdict = "violation";
      if (stale) {
        stale._used = true;
        p.note = `${p.note ? `${p.note}; ` : ""}allowlist entry #${stale._index} is for licence "${stale.license}" but the package now declares "${p.declared}" — re-review`;
      } else if (!p.note) {
        p.note = effective === "review" ? "weak copyleft / attribution licence — needs a reviewed allowlist entry" : `${effective} licence`;
      }
    }
    findings.push(p);
  }
  return findings;
}

// ─── Output ───────────────────────────────────────────────────────────────────────────────

function table(headers, rows) {
  const widths = headers.map((h, i) => Math.min(80, Math.max(h.length, ...rows.map((r) => String(r[i] ?? "").length))));
  const fmt = (cells) => cells.map((c, i) => {
    const s = String(c ?? "");
    return (s.length > widths[i] ? `${s.slice(0, widths[i] - 1)}…` : s).padEnd(widths[i]);
  }).join("  ");
  return [fmt(headers), widths.map((w) => "─".repeat(w)).join("  "), ...rows.map(fmt)].join("\n");
}

function mdEscape(s) {
  return String(s ?? "").replace(/\|/g, "\\|");
}

function purl(name, version) {
  const encoded = name.startsWith("@") ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${encoded}@${version}`;
}

function cyclonedx(root, packages, edges, rootPkg, now) {
  const refOf = new Map(packages.map((p) => [p.dir ?? `${p.name}@${p.version}`, purl(p.name, p.version)]));
  const seen = new Set();
  const components = [];
  for (const p of packages) {
    const ref = purl(p.name, p.version);
    if (seen.has(ref)) continue;
    seen.add(ref);
    const licenses = p.declared
      ? /\s(AND|OR|WITH)\s/i.test(p.declared) || p.declared.startsWith("(")
        ? [{ expression: p.declared.replace(/^\(|\)$/g, "") }]
        : [{ license: { id: normalizeId(p.declared) } }]
      : [];
    components.push({
      type: "library",
      "bom-ref": ref,
      name: p.name,
      version: p.version,
      purl: ref,
      scope: p.scope === "prod" ? "required" : "excluded",
      licenses,
      ...(p.homepage ? { externalReferences: [{ type: "website", url: p.homepage }] } : {}),
      properties: [
        { name: "bloody:license-class", value: p.cls },
        { name: "bloody:license-verdict", value: p.verdict },
        ...(p.inferredFrom ? [{ name: "bloody:license-inferred-from", value: p.inferredFrom }] : []),
      ],
    });
  }
  const dependencies = [];
  for (const [from, tos] of edges) {
    if (from.startsWith("workspace:")) continue;
    const ref = refOf.get(from);
    if (!ref) continue;
    dependencies.push({ ref, dependsOn: [...new Set([...tos].map((t) => refOf.get(t)).filter(Boolean))].sort() });
  }
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: now.toISOString(),
      tools: { components: [{ type: "application", name: TOOL.name, version: TOOL.version }] },
      component: { type: "application", "bom-ref": "bloody", name: rootPkg.name ?? "bloody", version: rootPkg.version ?? "0.0.0", licenses: [{ license: { name: "Proprietary — All rights reserved" } }] },
    },
    components,
    dependencies,
  };
}

export function main(argv = process.argv.slice(2)) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    console.error(`license-check: ${err.message}`);
    return 2;
  }
  if (opts.help) {
    console.log(readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(3, 31).map((l) => l.replace(/^ \* ?/, "")).join("\n"));
    return 0;
  }
  const now = new Date();
  const allowlist = loadAllowlist(opts.allowlist ?? join(REPO_ROOT, "scripts", "license-allowlist.json"));
  if (allowlist.errors.length > 0) {
    for (const e of allowlist.errors) console.error(`license-check: ${e}`);
    return 2;
  }

  const collected = opts.source === "pnpm" ? collectFromPnpm(REPO_ROOT) : collectFromFs(REPO_ROOT);
  let packages = collected.packages;
  if (opts.prod) packages = packages.filter((p) => p.scope === "prod");
  packages.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  if (packages.length === 0) {
    console.error("license-check: no installed dependencies found — run `pnpm install --frozen-lockfile` first");
    return 2;
  }

  const findings = evaluatePackages(packages, allowlist, now);
  const violations = findings.filter((p) => p.verdict === "violation");
  const unusedEntries = allowlist.entries.filter((e) => !e._used);

  // Summary by licence.
  const byLicense = new Map();
  for (const p of packages) {
    const key = p.declared ?? "(none)";
    const row = byLicense.get(key) ?? { cls: p.cls, prod: 0, dev: 0 };
    row[p.scope] += 1;
    byLicense.set(key, row);
  }
  const summaryRows = [...byLicense.entries()]
    .sort((a, b) => b[1].prod + b[1].dev - (a[1].prod + a[1].dev))
    .map(([lic, r]) => [lic, r.cls, r.prod, r.dev]);

  const prodCount = packages.filter((p) => p.scope === "prod").length;
  const devCount = packages.length - prodCount;
  if (!opts.quiet) {
    console.log(`Bloody licence gate — source: ${opts.source}${opts.prod ? " (production only)" : ""}, ${packages.length} packages (${prodCount} prod, ${devCount} dev)\n`);
    console.log(table(["Licence", "Class", "Prod", "Dev"], summaryRows));
    console.log("");
    if (opts.full) {
      console.log(table(["Package", "Version", "Scope", "Licence", "Class", "Verdict"], packages.map((p) => [p.name, p.version, p.scope, p.declared ?? "(none)", p.cls, p.verdict])));
      console.log("");
    }
    if (findings.length > 0) {
      console.log("Findings (violations, allowlisted, inferred, multi-licensed and attribution notices):\n");
      console.log(table(["Verdict", "Package", "Version", "Scope", "Licence", "Note", "Introduced via"], findings.map((p) => [p.verdict, p.name, p.version, p.scope, p.declared ?? "(none)", p.note ?? "", p.chain.slice(0, -1).join(" > ")])));
      console.log("");
    }
    for (const w of collected.warnings) console.log(`warning: ${w}`);
    for (const e of unusedEntries) console.log(`warning: allowlist entry #${e._index} (${e.package}) matched nothing — remove it`);
  }

  const report = {
    tool: TOOL,
    generatedAt: now.toISOString(),
    source: opts.source,
    prodOnly: opts.prod,
    totals: { packages: packages.length, prod: prodCount, dev: devCount, violations: violations.length, allowlisted: findings.filter((p) => p.verdict === "allowlisted").length },
    licenses: Object.fromEntries(summaryRows.map(([lic, cls, prod, dev]) => [lic, { class: cls, prod, dev }])),
    findings: findings.map(({ name, version, scope, declared, cls, verdict, note, chain }) => ({ name, version, scope, license: declared, class: cls, verdict, note: note ?? null, introducedVia: chain })),
    packages: packages.map(({ name, version, scope, declared, cls, verdict, inferredFrom }) => ({ name, version, scope, license: declared, class: cls, verdict, inferredFrom })),
    warnings: [...collected.warnings, ...unusedEntries.map((e) => `unused allowlist entry #${e._index} (${e.package})`)],
  };
  if (opts.json) writeFileSync(opts.json, `${JSON.stringify(report, null, 2)}\n`);
  if (opts.markdown) {
    const md = [
      `# npm dependency licence inventory`,
      ``,
      `Generated by \`node scripts/license-check.mjs --markdown\` on ${now.toISOString().slice(0, 10)} (source: ${opts.source}). Do not edit by hand.`,
      ``,
      `| Package | Version | Scope | Licence | Class | Verdict |`,
      `|---|---|---|---|---|---|`,
      ...packages.map((p) => `| ${mdEscape(p.name)} | ${mdEscape(p.version)} | ${p.scope} | ${mdEscape(p.declared ?? "(none)")} | ${p.cls} | ${p.verdict} |`),
      ``,
    ].join("\n");
    writeFileSync(opts.markdown, md);
  }
  if (opts.cyclonedx) {
    const rootPkg = readJson(join(REPO_ROOT, "package.json"));
    writeFileSync(opts.cyclonedx, `${JSON.stringify(cyclonedx(REPO_ROOT, packages, collected.edges, rootPkg, now), null, 2)}\n`);
  }

  if (violations.length > 0) {
    console.error(`\n✖ ${violations.length} licence violation(s). Replace the dependency, or add a reviewed entry to scripts/license-allowlist.json (see docs/LICENSES.md).`);
    return 1;
  }
  if (!opts.quiet) console.log(`✔ licence policy satisfied (${packages.length} packages, ${report.totals.allowlisted} allowlisted)`);
  return 0;
}

export { assessLicense, parseExpression, collectFromFs, evaluatePackages, loadAllowlist, purl };

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    process.exitCode = main();
  } catch (err) {
    console.error(`license-check: internal error: ${err instanceof Error ? err.stack : String(err)}`);
    process.exitCode = 2;
  }
}
