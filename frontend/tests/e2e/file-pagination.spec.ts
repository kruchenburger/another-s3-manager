import { test, expect } from "@playwright/test";
import { loginAsAdmin as login } from "./fixtures/auth-helpers";

const ROLE = process.env.E2E_MINIO_ROLE ?? "MinIO-e2e";
const BUCKET = process.env.E2E_MINIO_BUCKET ?? "e2e-test";

test.describe("Pagination via MinIO", () => {
  test("cold-loads the first page, then auto-loads the rest on scroll", async ({
    page,
  }) => {
    await login(page);
    await page.goto(`/v2/r/${ROLE}/b/${BUCKET}/p/pagination`);

    // First page renders fast: file-001 is in the first 200.
    const firstRow = page.locator("tr").filter({ hasText: "file-001.txt" });
    await expect(firstRow).toBeVisible({ timeout: 15_000 });

    // file-200 is the last item on page 1 (items_per_page=200).
    await expect(
      page.locator("tr").filter({ hasText: "file-200.txt" }),
    ).toBeVisible();

    // file-250 lives on page 2 — NOT yet rendered before we scroll.
    await expect(
      page.locator("tr").filter({ hasText: "file-250.txt" }),
    ).toHaveCount(0);

    // Scroll the last loaded row into view — the sentinel in the table footer
    // intersects and triggers fetchNextPage (enable_lazy_loading=true in the
    // e2e config).
    await page
      .locator("tr")
      .filter({ hasText: "file-200.txt" })
      .scrollIntoViewIfNeeded();

    // Page 2 loads — file-250 now visible.
    await expect(
      page.locator("tr").filter({ hasText: "file-250.txt" }),
    ).toBeVisible({ timeout: 10_000 });
  });
});
