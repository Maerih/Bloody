// SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
// Copyright (c) 2026 Bloody. All rights reserved.
// Run: node --test scripts/
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { assessLicense, purl } from "./license-check.mjs";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "license-check.mjs");

describe("assessLicense (SPDX evaluation)", () => {
  const cases = [
    ["MIT", "permissive"],
    ["Apache-2.0", "permissive"],
    ["(MIT AND Zlib)", "permissive"],
    ["MIT AND ISC", "permissive"],
    ["(MIT OR GPL-3.0-only)", "permissive"],
    ["GPL-3.0-only OR Apache-2.0", "permissive"],
    ["MIT/Apache-2.0", "permissive"],
    ["Apache 2.0", "permissive"],
    ["BSL-1.0", "permissive"], // Boost Software License
    ["CC-BY-4.0", "attribution"],
    ["MPL-2.0", "review"],
    ["(MPL-2.0 OR Apache-2.0)", "permissive"],
    ["GPL-2.0-only", "denied"],
    ["GPL-2.0+", "denied"],
    ["AGPL-3.0-or-later", "denied"],
    ["LGPL-2.1-only", "denied"],
    ["(LGPL-2.1-only AND MIT)", "denied"],
    ["SSPL-1.0", "denied"],
    ["BUSL-1.1", "denied"],
    ["BSL-1.1", "denied"], // Business Source mis-tagged with the Boost prefix
    ["Elastic-2.0", "denied"],
    ["CC-BY-NC-4.0", "denied"],
    ["CC-BY-SA-4.0", "denied"],
    ["GPL-2.0-only WITH Classpath-exception-2.0", "denied"],
    ["Apache-2.0 WITH LLVM-exception", "permissive"],
    ["UNLICENSED", "unknown"],
    ["SEE LICENSE IN LICENSE.md", "unknown"],
    ["Some-Custom-Licence", "unknown"],
    ["(MIT", "unknown"],
    ["", "unknown"],
  ];
  for (const [expr, cls] of cases) {
    it(`${JSON.stringify(expr)} → ${cls}`, () => assert.equal(assessLicense(expr).cls, cls));
  }

  it("records the permissive alternative of a dual licence", () => {
    const r = assessLicense("(GPL-2.0-only OR MIT)");
    assert.deepEqual(r.chosen, ["MIT"]);
    assert.match(r.note ?? "", /multi-licensed; used under MIT/);
  });

  it("builds npm purls with encoded scopes", () => {
    assert.equal(purl("@fastify/cors", "10.1.0"), "pkg:npm/%40fastify/cors@10.1.0");
    assert.equal(purl("pg", "8.13.1"), "pkg:npm/pg@8.13.1");
  });
});

describe("license-check CLI on fixture repositories", () => {
  const roots = [];
  after(() => roots.forEach((r) => rmSync(r, { recursive: true, force: true })));

  /** Create a fake workspace: root package.json + node_modules/<name>/package.json (+ optional LICENSE). */
  function fixture({ dependencies = {}, devDependencies = {}, modules = {}, allowlist }) {
    const root = mkdtempSync(join(tmpdir(), "bloody-lic-"));
    roots.push(root);
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0", private: true, dependencies, devDependencies }));
    for (const [name, spec] of Object.entries(modules)) {
      const dir = join(root, "node_modules", name);
      mkdirSync(dir, { recursive: true });
      const pkg = { name, version: spec.version ?? "1.0.0", dependencies: spec.dependencies ?? {} };
      if (spec.license !== undefined) pkg.license = spec.license;
      writeFileSync(join(dir, "package.json"), JSON.stringify(pkg));
      if (spec.licenseText) writeFileSync(join(dir, "LICENSE"), spec.licenseText);
    }
    mkdirSync(join(root, "scripts"), { recursive: true });
    if (allowlist) writeFileSync(join(root, "scripts", "license-allowlist.json"), JSON.stringify({ entries: allowlist }));
    return root;
  }

  function run(root, args = []) {
    const out = join(root, "report.json");
    const res = spawnSync(process.execPath, [SCRIPT, "--json", out, ...args], { env: { ...process.env, BLOODY_LICENSE_CHECK_ROOT: root }, encoding: "utf8" });
    let report = null;
    try {
      report = JSON.parse(readFileSync(out, "utf8"));
    } catch {
      /* no report on usage errors */
    }
    return { status: res.status, stdout: res.stdout, stderr: res.stderr, report };
  }

  it("passes a permissive tree and infers licences from LICENSE text", () => {
    const root = fixture({
      dependencies: { a: "1", b: "1" },
      modules: {
        a: { license: "MIT", dependencies: { c: "1" } },
        b: { license: "(Apache-2.0 OR GPL-2.0-only)" },
        c: { licenseText: "Permission is hereby granted, free of charge, to any person obtaining a copy of this software" },
      },
    });
    const r = run(root);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.report.totals.packages, 3);
    const c = r.report.packages.find((p) => p.name === "c");
    assert.equal(c.license, "MIT");
    assert.equal(c.inferredFrom, "LICENSE");
  });

  it("fails on a transitive AGPL dependency and reports how it was introduced", () => {
    const root = fixture({
      dependencies: { a: "1" },
      modules: { a: { license: "MIT", dependencies: { evil: "1" } }, evil: { license: "AGPL-3.0-only", version: "2.0.0" } },
    });
    const r = run(root);
    assert.equal(r.status, 1);
    const f = r.report.findings.find((x) => x.name === "evil");
    assert.equal(f.verdict, "violation");
    assert.deepEqual(f.introducedVia, [".", "a@1.0.0", "evil@2.0.0"]);
  });

  it("treats packages without any licence metadata as unknown (violation)", () => {
    const root = fixture({ dependencies: { mystery: "1" }, modules: { mystery: {} } });
    const r = run(root);
    assert.equal(r.status, 1);
    assert.equal(r.report.findings[0].class, "unknown");
  });

  it("classifies dev-only vs prod scope and supports --prod", () => {
    const root = fixture({
      dependencies: { a: "1" },
      devDependencies: { tool: "1" },
      modules: { a: { license: "MIT" }, tool: { license: "GPL-3.0-only" } },
    });
    assert.equal(run(root).status, 1, "dev-only GPL still fails the full gate");
    const prodOnly = run(root, ["--prod"]);
    assert.equal(prodOnly.status, 0);
    assert.equal(prodOnly.report.totals.packages, 1);
  });

  it("allows CC-BY data in dev tooling but requires review when shipped", () => {
    const dev = fixture({ devDependencies: { data: "1" }, modules: { data: { license: "CC-BY-4.0" } } });
    assert.equal(run(dev).status, 0);
    const prod = fixture({ dependencies: { data: "1" }, modules: { data: { license: "CC-BY-4.0" } } });
    assert.equal(run(prod).status, 1);
  });

  it("honours a reviewed allowlist entry for weak copyleft, pinned to the declared licence", () => {
    const entry = { package: "mplpkg", license: "MPL-2.0", justification: "Used unmodified as a separate file; MPL file-level obligations reviewed.", approvedBy: "legal@bloody.example" };
    const ok = fixture({ dependencies: { mplpkg: "1" }, modules: { mplpkg: { license: "MPL-2.0" } }, allowlist: [entry] });
    const r = run(ok);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(r.report.totals.allowlisted, 1);

    const relicensed = fixture({ dependencies: { mplpkg: "1" }, modules: { mplpkg: { license: "BUSL-1.1" } }, allowlist: [entry] });
    const r2 = run(relicensed);
    assert.equal(r2.status, 1);
    assert.match(r2.report.findings[0].note, /re-review/);
  });

  it("requires an exceptionRef before a denied licence can be allowlisted, and enforces expiry", () => {
    const base = { package: "gplpkg", license: "GPL-2.0-only", justification: "Isolated CLI invoked as a separate process only.", approvedBy: "cto" };
    const noRef = fixture({ dependencies: { gplpkg: "1" }, modules: { gplpkg: { license: "GPL-2.0-only" } }, allowlist: [base] });
    assert.equal(run(noRef).status, 1);
    const withRef = fixture({ dependencies: { gplpkg: "1" }, modules: { gplpkg: { license: "GPL-2.0-only" } }, allowlist: [{ ...base, exceptionRef: "ADR-0004#exceptions" }] });
    assert.equal(run(withRef).status, 0);
    const expired = fixture({ dependencies: { gplpkg: "1" }, modules: { gplpkg: { license: "GPL-2.0-only" } }, allowlist: [{ ...base, exceptionRef: "ADR-0004", expires: "2020-01-01" }] });
    const r = run(expired);
    assert.equal(r.status, 1);
    assert.match(r.report.findings[0].note, /expired/);
  });

  it("rejects malformed allowlist entries with exit code 2", () => {
    const root = fixture({ dependencies: { a: "1" }, modules: { a: { license: "MIT" } }, allowlist: [{ package: "a", license: "MIT" }] });
    assert.equal(run(root).status, 2);
  });

  it("emits a CycloneDX 1.5 SBOM with scopes and dependency edges", () => {
    const root = fixture({
      dependencies: { "@scope/a": "1" },
      devDependencies: { t: "1" },
      modules: { "@scope/a": { license: "MIT", dependencies: { b: "1" } }, b: { license: "ISC" }, t: { license: "MIT" } },
    });
    const sbomFile = join(root, "sbom.json");
    const r = run(root, ["--cyclonedx", sbomFile]);
    assert.equal(r.status, 0);
    const sbom = JSON.parse(readFileSync(sbomFile, "utf8"));
    assert.equal(sbom.bomFormat, "CycloneDX");
    assert.equal(sbom.specVersion, "1.5");
    const a = sbom.components.find((c) => c.name === "@scope/a");
    assert.equal(a.purl, "pkg:npm/%40scope/a@1.0.0");
    assert.equal(a.scope, "required");
    assert.equal(sbom.components.find((c) => c.name === "t").scope, "excluded");
    assert.deepEqual(sbom.dependencies.find((d) => d.ref === a.purl).dependsOn, ["pkg:npm/b@1.0.0"]);
  });
});
