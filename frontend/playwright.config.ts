import { defineConfig, devices } from "@playwright/test";

/**
 * E2E env contract:
 * - E2E_BASE_URL          Base URL of the app (default http://localhost:8080)
 * - E2E_ADMIN_USERNAME    Admin user for login (default 'admin')
 * - E2E_ADMIN_PASSWORD    Admin password (default 'TestPass1' — policy-compliant)
 * - E2E_MINIO_ROLE        Role name in config that points to MinIO (default 'MinIO-e2e')
 * - E2E_MINIO_BUCKET      Bucket name with seeded fixtures (default 'e2e-test')
 *
 * Locally:
 *   docker compose -f docker-compose.yml -f docker-compose.minio.yml up --build -d
 *   # add a MinIO-e2e role to data/config.json (or via the admin UI):
 *   # {"name":"MinIO-e2e","type":"s3_compatible","access_key_id":"minioadmin",
 *   #  "secret_access_key":"minioadmin","endpoint_url":"http://minio:9000",
 *   #  "addressing_style":"path","allowed_buckets":["e2e-test"]}
 *   cd frontend && npx playwright test
 */
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
  // No webServer: backend must be started before Playwright runs.
  // Locally: `docker compose -f docker-compose.yml -f docker-compose.minio.yml up`.
  // CI (.github/workflows/ci.yml `e2e` job): backend started via `nohup uv run ... &`.
});
