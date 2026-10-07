import { defineConfig } from "tsup";

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
});
