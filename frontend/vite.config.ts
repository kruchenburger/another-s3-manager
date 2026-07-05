import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

// Build output goes directly into the FastAPI static/app dir served by the
// root SPA catch-all in main.py, so the multi-stage Dockerfile only needs to
// copy this one folder.
export default defineConfig({
  plugins: [react()],
  base: "/",
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  build: {
    outDir: "../src/another_s3_manager/static/app",
    emptyOutDir: true,
    sourcemap: true,
    rollupOptions: {
      output: {
        // Split vendor libs into separate chunks so browsers can cache them
        // independently of our app code — bumping a UI component shouldn't
        // bust the cached Mantine chunk (~400 KB). Keeps the main entrypoint
        // under the 500 KB warning threshold and improves cold-load TTFB by
        // letting the browser parallelise downloads. Note: GSAP is included
        // because `@gsap/react` pulls in `gsap` for the BurgerLogo animation.
        manualChunks: {
          react: ["react", "react-dom", "react-router-dom"],
          mantine: [
            "@mantine/core",
            "@mantine/hooks",
            "@mantine/form",
            "@mantine/notifications",
            "@mantine/dropzone",
          ],
          tanstack: ["@tanstack/react-query"],
          icons: ["lucide-react"],
          gsap: ["gsap", "@gsap/react"],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8080", changeOrigin: true },
      "/health": { target: "http://localhost:8080", changeOrigin: true },
    },
  },
});
