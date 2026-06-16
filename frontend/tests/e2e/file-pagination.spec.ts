import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { ADMIN_USER, ADMIN_PASSWORD } from "./fixtures/auth-helpers";

const ROLE = process.env.E2E_MINIO_ROLE ?? "MinIO-e2e";
const BUCKET = process.env.E2E_MINIO_BUCKET ?? "e2e-test";

// Inline login (not the shared loginAsAdmin): that helper asserts the post-login
// URL is exactly /v2/, but an admin with role access auto-redirects to the
// default role/bucket (the e2e config has the MinIO-e2e role), so that URL never
// holds. Assert success via the "User menu" button instead. Mirrors
// ministack.spec.ts and file-prefix-search.spec.ts.
async function login(page: Page): Promise<void> {
  await page.goto("/v2/login");
  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password", { exact: true }).fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Login" }).click();
  await expect(page.getByLabel("User menu")).toBeVisible({ timeout: 15_000 });
}

test.describe("Hybrid pagination via MinIO", () => {
  test("truncated folder shows N+ count and Load all loads the rest", async ({
    page,
  }) => {
    await login(page);
    await page.goto(`/v2/r/${ROLE}/b/${BUCKET}/p/pagination`);

    // First client-load chunk (max_client_load=50 in the e2e config) loads fast.
    await expect(
      page.locator("tr").filter({ hasText: "file-001.txt" }),
    ).toBeVisible({ timeout: 15_000 });

    // The seed has 250 objects > the 50-object client-load limit, so the header
    // shows an honest "N+ objects" counter (never a fabricated total).
    await expect(page.getByText(/\+ objects/)).toBeVisible();

    // Load more / Load all live in the header — always visible, no scrolling
    // through 50 rows to reach them.
    const loadAll = page.getByRole("button", { name: /load all/i });
    await expect(loadAll).toBeVisible();

    // file-250 is past the first chunk — not loaded into memory yet.
    await expect(
      page.locator("tr").filter({ hasText: "file-250.txt" }),
    ).toHaveCount(0);

    // Drain the whole folder from the server.
    await loadAll.click();

    // After draining, the last object is in memory. With lazy loading on the
    // client-side slice auto-grows on scroll; scroll the in-memory list to the
    // bottom so file-250 renders.
    await expect(async () => {
      // Hover the table first so the wheel event lands on the internal scroll
      // container (PR #44). page.mouse.wheel dispatches at the current cursor
      // position, which defaults to the top-left corner — over the sidebar, not
      // the file list — so without this the scroll goes nowhere.
      await page.locator("table").hover();
      await page.mouse.wheel(0, 100_000);
      await expect(
        page.locator("tr").filter({ hasText: "file-250.txt" }),
      ).toBeVisible({ timeout: 2_000 });
    }).toPass({ timeout: 20_000 });
  });
});
