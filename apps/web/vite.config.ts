import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

/**
 * Bloody Command Center — Vite configuration.
 *
 * Dev: `/api` is proxied to the control plane (default http://localhost:4000, override with
 * BLOODY_API_URL) so the session cookie and CSRF cookie are first-party.
 * Build: no production source maps (proprietary code), vendor chunks split for caching.
 */
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiTarget = env.BLOODY_API_URL ?? "http://localhost:4000";
  return {
    plugins: [react()],
    server: {
      port: 5173,
      strictPort: false,
      proxy: {
        "/api": { target: apiTarget, changeOrigin: false, secure: true, ws: true },
      },
    },
    preview: {
      port: 4173,
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
