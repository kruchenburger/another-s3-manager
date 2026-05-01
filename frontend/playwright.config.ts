import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false, // tests share the same backend DB; run sequentially to avoid races
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:8080",
    trace: "on-first-retry",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    // mobile project disabled for Phase 3b — re-enable in Phase 7 with mobile-specific specs
  ],
  // No webServer: assume `docker compose up` is run by the developer or CI before `npm run test:e2e`
});
