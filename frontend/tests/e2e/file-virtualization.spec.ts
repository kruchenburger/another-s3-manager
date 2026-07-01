import { test, expect } from "@playwright/test";
import { loginAsAdmin as login } from "./fixtures/auth-helpers";

const ROLE = process.env.E2E_MINIO_ROLE ?? "MinIO-e2e";
const BUCKET = process.env.E2E_MINIO_BUCKET ?? "e2e-test";

test.describe("FileBrowser scroll container + virtualization", () => {
  test("toolbar stays pinned and the list virtualizes on a large folder", async ({
    page,
  }) => {
    await login(page);
    // 250-object folder, cap=50: Load all drains it in 5 fast fetches.
    await page.goto(`/v2/r/${ROLE}/b/${BUCKET}/p/pagination`);

    await expect(
      page.locator("tr").filter({ hasText: "file-001.txt" }),
    ).toBeVisible({ timeout: 15_000 });

    await page.getByRole("button", { name: /more load options/i }).click();
    await page.getByRole("menuitem", { name: /load all/i }).click();
    // Wait until the truncation marker is gone (everything loaded).
    await expect(page.getByText(/\+ objects/)).toHaveCount(0, { timeout: 20_000 });

    // Virtualization: 250 objects are loaded but only a window renders.
    const renderedRows = page.locator("table tbody tr:not([data-spacer])");
    const countAfterLoad = await renderedRows.count();
    expect(countAfterLoad).toBeLessThan(80); // ~window+overscan, not 250

    // The toolbar (filter input) is OUTSIDE the scroll area — it must stay
    // visible after scrolling the list to the bottom (the regression fix).
    const filter = page.getByPlaceholder(/filter files/i);
    await expect(filter).toBeVisible();
    await page
      .locator('[class*="scrollArea"]')
      .evaluate((el) => (el.scrollTop = el.scrollHeight));
    await expect(filter).toBeVisible();

    // DOM stays bounded after scrolling (still windowed, not all 250).
    expect(await renderedRows.count()).toBeLessThan(80);
  });

  test("lazy scroll auto-loads subsequent server chunks (no Load more click)", async ({
    page,
  }) => {
    await login(page);
    // 10k folder, cap=50: scrolling must pull chunk after chunk automatically.
    await page.goto(`/v2/r/${ROLE}/b/${BUCKET}/p/virtualization`);

    await expect(
      page.locator("tr").filter({ hasText: "vfile-00001.txt" }),
    ).toBeVisible({ timeout: 15_000 });

    // vfile-00051 is in the SECOND server chunk — not loaded yet.
    await expect(
      page.locator("tr").filter({ hasText: "vfile-00051.txt" }),
    ).toHaveCount(0);

    // Scroll the list down repeatedly; lazy auto-load should fetch the next
    // chunk(s) without ever clicking "Load more".
    const scrollArea = page.locator('[class*="scrollArea"]');
    await expect(async () => {
      await scrollArea.evaluate((el) => (el.scrollTop = el.scrollTop + 4000));
      await expect(
        page.locator("tr").filter({ hasText: "vfile-00051.txt" }),
      ).toBeVisible({ timeout: 2_000 });
    }).toPass({ timeout: 25_000 });
  });
});
