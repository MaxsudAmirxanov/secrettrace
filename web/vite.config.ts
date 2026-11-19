/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The API runs on :8080 in development (`secrettrace-server serve`); the dev server
// proxies /api so the session cookie stays same-origin (SameSite=Strict).
const api = process.env.ST_API_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: { "/api": { target: api, changeOrigin: false } },
  },
  build: {
    outDir: "dist",
    assetsDir: "assets",
    sourcemap: false,
    // No inline scripts or data: modules: the server's CSP is script-src 'self'.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    target: "es2022",
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    restoreMocks: true,
  },
});
