import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

// Build output goes directly into the FastAPI static/v2 mount so the multi-stage
// Dockerfile only needs to copy this one folder. Base "/v2/" matches the mount path.
export default defineConfig({
  plugins: [react()],
  base: "/v2/",
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  build: {
    outDir: "../src/another_s3_manager/static/v2",
    emptyOutDir: true,
    sourcemap: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8080", changeOrigin: true },
      "/health": { target: "http://localhost:8080", changeOrigin: true },
    },
  },
});
