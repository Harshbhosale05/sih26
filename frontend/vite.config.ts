import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The API runs on :8000 (docker compose). Proxying /api keeps the browser on a
// single origin in development, so no CORS configuration is needed.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      ["/api", "/docs", "/openapi.json"].map((path) => [
        path,
        { target: process.env.VITE_API_TARGET ?? "http://localhost:8000", changeOrigin: true },
      ]),
    ),
  },
});
