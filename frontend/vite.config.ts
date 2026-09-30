import path from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The API runs on :8000 (docker compose). Proxying /api keeps the browser on a
// single origin in development, so no CORS configuration is needed.
export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(__dirname, "./src") } },
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      ["/api", "/docs", "/openapi.json"].map((p) => [
        p,
        { target: process.env.VITE_API_TARGET ?? "http://localhost:8000", changeOrigin: true },
      ]),
    ),
  },
});
