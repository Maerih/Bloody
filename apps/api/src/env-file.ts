import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { parseEnv } from "node:util";

/**
 * Load the nearest `.env` file (current directory, then up to `maxDepth` parents — so
 * `pnpm --filter @bloody/api …`, which runs in apps/api, finds the repo-root `.env`).
 * Variables already present in the environment always win; nothing is overwritten.
 * Returns the file that was loaded, or null when none exists.
 */
export function loadDotEnv(startDir: string = process.cwd(), maxDepth = 3): string | null {
  if (process.env.BLOODY_SKIP_DOTENV === "1") return null;
  let dir = path.resolve(startDir);
  for (let i = 0; i <= maxDepth; i++) {
    const file = path.join(dir, ".env");
    if (existsSync(file)) {
      const values = parseEnv(readFileSync(file, "utf8"));
      for (const [key, value] of Object.entries(values)) {
        if (process.env[key] === undefined) process.env[key] = value;
      }
      return file;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}
