import { isIP } from "node:net";
import path from "node:path";
import { defineConfig, loadEnv, type CorsOptions } from "vite";
import react from "@vitejs/plugin-react";

/**
 * Bloody Command Center — Vite configuration.
 *
 * Dev: `/api` is proxied to the control plane (default http://localhost:4000, override with
 * BLOODY_API_URL) so the session cookie and CSRF cookie are first-party.
 * Build: no production source maps (proprietary code), vendor chunks split for caching.
 */
export default defineConfig(({ mode }) => {
  // Settings come from apps/web/.env* and, with lower precedence, the repo-root .env.
  const env = { ...loadEnv(mode, path.resolve(process.cwd(), "../.."), ""), ...loadEnv(mode, process.cwd(), ""), ...process.env } as Record<string, string | undefined>;
  const apiTarget = env.BLOODY_API_URL || "http://localhost:4000";
  // BLOODY_WEB_HOST=0.0.0.0 serves the UI on every interface (e.g. http://<server-ip>:5173).
  const host = env.BLOODY_WEB_HOST || "localhost";
  // Extra hostnames (DNS names) allowed to reach the dev server; IP addresses are always allowed.
  const allowedHosts = (env.BLOODY_WEB_ALLOWED_HOSTS || "").split(",").map((h) => h.trim()).filter(Boolean);
  // Browser origins allowed to talk to the dev server (incl. the live-reload websocket): any IP
  // address the server is reached on (it may change), localhost, the allowed DNS names and
  // PUBLIC_URL / BLOODY_WEB_ORIGINS. DNS names stay limited to allowedHosts (DNS-rebinding guard).
  const extraOrigins = [env.PUBLIC_URL || env.BLOODY_PUBLIC_URL, ...(env.BLOODY_WEB_ORIGINS || "").split(",")]
    .map((o) => (o || "").trim())
    .filter(Boolean)
    .map((o) => new URL(o).origin);
  const originAllowed = (origin: string): boolean => {
    if (extraOrigins.includes(origin)) return true;
    let hostname: string;
    try {
      hostname = new URL(origin).hostname.toLowerCase().replace(/^\[|\]$/g, "");
    } catch {
      return false;
    }
    if (hostname === "localhost" || hostname.endsWith(".localhost") || isIP(hostname)) return true;
    return allowedHosts.some((h) => (h.startsWith(".") ? hostname.endsWith(h) || hostname === h.slice(1) : hostname === h.toLowerCase()));
  };
  const cors: CorsOptions = { origin: (origin, cb) => cb(null as unknown as Error, !origin || originAllowed(origin)) };
  return {
    plugins: [react()],
    server: {
      host,
      port: Number(env.BLOODY_WEB_PORT) || 5173,
      strictPort: false,
      allowedHosts,
      cors,
      proxy: {
        "/api": { target: apiTarget, changeOrigin: false, secure: true, ws: true },
      },
    },
    preview: {
      host,
      port: 4173,
      allowedHosts,
      proxy: {
        "/api": { target: apiTarget, changeOrigin: false },
      },
    },
    build: {
      outDir: "dist",
      sourcemap: false,
      target: "es2022",
      chunkSizeWarningLimit: 900,
      rollupOptions: {
        output: {
          manualChunks: {
            react: ["react", "react-dom", "react-router-dom"],
            query: ["@tanstack/react-query"],
            charts: ["recharts"],
            graph: ["@xyflow/react"],
          },
        },
      },
    },
  };
});
