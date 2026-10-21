import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { defineConfig } from "tsup";

// npm dependencies of the bundled workspace packages stay external too (the image installs the
// @bloody/api closure, which includes them): bundling CommonJS packages into the ESM output fails
// at start-up ("Dynamic require of … is not supported").
const packagesDir = path.resolve(__dirname, "../../packages");
const workspaceDeps = readdirSync(packagesDir).flatMap((dir) => {
  try {
    const pkg = JSON.parse(readFileSync(path.join(packagesDir, dir, "package.json"), "utf8")) as { dependencies?: Record<string, string> };
    return Object.keys(pkg.dependencies ?? {}).filter((d) => !d.startsWith("@bloody/"));
  } catch {
    return [];
  }
});

// Bundle the proprietary workspace packages into the API artifact; keep npm deps external.
export default defineConfig({
  entry: ["src/server.ts", "src/db/migrate.ts"],
  format: ["esm"],
  platform: "node",
  target: "node22",
  outDir: "dist",
  sourcemap: true,
  clean: true,
  noExternal: [/^@bloody\//],
  external: [...new Set(workspaceDeps)],
});
