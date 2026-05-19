import { test, expect } from "@playwright/test";
import { loginAsAdmin as login } from "./fixtures/auth-helpers";

const ROLE = process.env.E2E_MINIO_ROLE ?? "MinIO-e2e";
const BUCKET = process.env.E2E_MINIO_BUCKET ?? "e2e-test";

test.describe("Upload + delete via MinIO", () => {
  test("upload a file then delete it", async ({ page }) => {
    await login(page);
    await page.goto(`/v2/r/${ROLE}/b/${BUCKET}`);

    // File table is the main file listing UI
    await page.locator("table").waitFor();

    // Upload a uniquely-named file so we don't collide with seeded fixtures.
    // Using a timestamp keeps the spec re-runnable without manual cleanup if delete fails.
    const uploadName = `upload-${Date.now()}.txt`;

    // The hidden <input type="file"> lives in FileBrowser.tsx and is triggered
    // via ref by the Upload button's onClick. There is exactly one role=button
    // with name "Upload" on the page, so getByRole is the stable hook.
    const fileChooserPromise = page.waitForEvent("filechooser");
    await page.getByRole("button", { name: "Upload" }).click();
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
