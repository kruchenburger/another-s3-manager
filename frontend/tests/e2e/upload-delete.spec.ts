import { test, expect } from "@playwright/test";
import { loginAsAdmin as login } from "./fixtures/auth-helpers";

const ROLE = process.env.E2E_MINIO_ROLE ?? "MinIO-e2e";
const BUCKET = process.env.E2E_MINIO_BUCKET ?? "e2e-test";

test.describe("Upload + delete via MinIO", () => {
  test("upload a file then delete it", async ({ page }) => {
    await login(page);
    await page.goto(`/r/${ROLE}/b/${BUCKET}`);

    // File table is the main file listing UI
    await page.locator("table").waitFor();

    // Upload a uniquely-named file so we don't collide with seeded fixtures.
    // Using a timestamp keeps the spec re-runnable without manual cleanup if delete fails.
    const uploadName = `upload-${Date.now()}.txt`;

    // The hidden <input type="file"> lives in FileBrowser.tsx and is triggered
    // via ref by the UploadSplitButton primary's onClick. Use exact:true so the
    // name doesn't also match the "More upload options" chevron (substring).
    // First Upload click in a fresh browser context opens the drag-and-drop
    // hint modal (its localStorage dismiss flag is never set in Playwright's
    // isolated context) — the native file chooser opens from the modal's CTA.
    await page.getByRole("button", { name: "Upload", exact: true }).click();
    const fileChooserPromise = page.waitForEvent("filechooser");
    await page
      .getByRole("dialog", { name: "Upload files" })
      .getByRole("button", { name: "Choose files" })
      .click();
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

  test("2 MB upload exercises the disk-spool + multipart streaming path", async ({
    page,
  }) => {
    await login(page);
    await page.goto(`/r/${ROLE}/b/${BUCKET}`);

    // File table is the main file listing UI
    await page.locator("table").waitFor();

    const uploadName = `upload-large-${Date.now()}.bin`;

    // Same first-upload dance as above: fresh context → drag-and-drop hint
    // modal opens first, file chooser comes from the modal's CTA.
    await page.getByRole("button", { name: "Upload", exact: true }).click();
    const fileChooserPromise = page.waitForEvent("filechooser");
    await page
      .getByRole("dialog", { name: "Upload files" })
      .getByRole("button", { name: "Choose files" })
      .click();
    const fileChooser = await fileChooserPromise;
    // 2 MiB — over Starlette's 1 MiB spool_max_size, so the request body
    // spools to DISK and streams through upload_fileobj (managed multipart)
    // end-to-end. In-memory buffer: no fixture file, keeps the repo slim.
    await fileChooser.setFiles({
      name: uploadName,
      mimeType: "application/octet-stream",
      buffer: Buffer.alloc(2 * 1024 * 1024, "a"),
    });

    // Verify file appears in the table (give backend time — multipart upload
    // of a larger payload can take longer than the plain-text upload above)
    const uploadedRow = page.locator("tr").filter({ hasText: uploadName });
    await expect(uploadedRow).toBeVisible({ timeout: 30_000 });
    // formatBytes renders 2 MiB (2097152 bytes) as "2.0 MB" — proves the
    // FULL body landed in the bucket, not a truncated stream.
    await expect(uploadedRow).toContainText("2.0 MB");

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
