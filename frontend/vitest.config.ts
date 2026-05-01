import { defineConfig, mergeConfig } from "vitest/config";
import viteConfig from "./vite.config";

// mergeConfig inherits all Vite plugins (including @vitejs/plugin-react),
// resolve.alias, and other build settings — so JSX transform + `@/*` paths
// work identically in tests and production. Phase 2 dropped the react plugin
// to dodge a vitest 2 ↔ vite 6 type clash; mergeConfig is the proper escape.
export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "jsdom",
      globals: true,
      setupFiles: ["./src/setupTests.ts"],
      css: true,
    },
  }),
);
