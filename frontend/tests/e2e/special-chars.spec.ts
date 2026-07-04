import { test, expect } from "@playwright/test";
import { loginAsAdmin as login } from "./fixtures/auth-helpers";

const ROLE = process.env.E2E_MINIO_ROLE ?? "MinIO-e2e";
const BUCKET = process.env.E2E_MINIO_BUCKET ?? "e2e-test";
const SPECIAL_NAME = "test:colon#hash?question.txt";

test.describe("Special characters in S3 keys", () => {
  test("file with : # ? in name uploads, renders, downloads, deletes", async ({ page }) => {
    await login(page);
    await page.goto(`/r/${ROLE}/b/${BUCKET}`);

    await page.locator("table").waitFor();

    // Upload the special-chars file ourselves via in-memory buffer.
    // This makes the test idempotent (works on retry without re-seeding) and
    // sidesteps the NTFS limitation that prevents committing a fixture file
    // with ':' '?' in its name (Windows forbids those chars).
    const fileChooserPromise = page.waitForEvent("filechooser");
    await page.getByRole("button", { name: "Upload", exact: true }).click();
    const fileChooser = await fileChooserPromise;
    await fileChooser.setFiles({
      name: SPECIAL_NAME,
      mimeType: "text/plain",
      buffer: Buffer.from("special chars regression fixture"),
    });

    // Scope all interactions to the row so per-row buttons resolve unambiguously.
    const row = page.locator("tr").filter({ hasText: SPECIAL_NAME });
    await expect(row).toBeVisible({ timeout: 15_000 });

    // Download — verify the browser download triggers (the hard part is the URL encoding).
    // Chrome sanitizes ':' and '?' to '_' in the saved filename, so we check for the
    // recognizable stem rather than the exact original name. The fact that the download
    // arrives at all proves the URL-encoded round-trip through the FastAPI endpoint works.
    const downloadPromise = page.waitForEvent("download");
    await row.hover();
    await row.getByRole("button", { name: "Download" }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/test.colon/);
    const path = await download.path();
    expect(path).toBeTruthy();

    // Delete — verifies the special chars round-trip through the delete API too
    await row.hover();
    await row.getByRole("button", { name: "Delete" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Delete" }).click();
    await expect(row).not.toBeVisible({ timeout: 10_000 });
  });
});
