import { test, expect } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USERNAME ?? "admin";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "test";
const ROLE = process.env.E2E_MINIO_ROLE ?? "MinIO-e2e";
const BUCKET = process.env.E2E_MINIO_BUCKET ?? "e2e-test";

async function login(page: import("@playwright/test").Page): Promise<void> {
  await page.goto("/v2/login");
  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password").fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Login" }).click();
  await page.waitForURL(/\/v2\/?$/);
}

test.describe("Upload + delete via MinIO", () => {
  test("upload a file then delete it", async ({ page }) => {
    await login(page);
    await page.goto(`/v2/r/${ROLE}/b/${BUCKET}`);

    // File table is the main file listing UI
    await page.locator("table").waitFor();

    // Upload a uniquely-named file so we don't collide with seeded fixtures.
    // Using a timestamp keeps the spec re-runnable without manual cleanup if delete fails.
    const uploadName = `upload-${Date.now()}.txt`;

    // Click Upload (data-tour selector is most stable). The hidden <input type="file">
    // lives in FileBrowser.tsx and is triggered via ref by the Upload button onClick.
    const fileChooserPromise = page.waitForEvent("filechooser");
    await page.locator('[data-tour="upload-btn"]').click();
    const fileChooser = await fileChooserPromise;
    // Playwright lets us set virtual file content — avoids needing a fixture with this exact name.
    await fileChooser.setFiles({
      name: uploadName,
      mimeType: "text/plain",
      buffer: Buffer.from("playwright upload test"),
    });

    // Verify file appears in the table (give backend time)
    const uploadedRow = page.locator("tr").filter({ hasText: uploadName });
    await expect(uploadedRow).toBeVisible({ timeout: 15_000 });

    // Hover the row to reveal Delete icon (CSS opacity transition on row hover), then click
    // the per-row Delete (scoped via the row locator so we never click the wrong row).
    await uploadedRow.hover();
    await uploadedRow.getByRole("button", { name: "Delete" }).click();

    // Confirm in modal — scope to dialog to avoid matching the row Delete again
    await page.getByRole("dialog").getByRole("button", { name: "Delete" }).click();

    // Verify it's gone
    await expect(uploadedRow).not.toBeVisible({ timeout: 10_000 });
  });
});
