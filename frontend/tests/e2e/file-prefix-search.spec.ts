/**
 * E2E: server-side prefix search (/v2 "Search on server" affordance).
 *
 * Precondition: the pagination seed folder (e2e-test/pagination/) contains
 * file-001.txt … file-250.txt. The CI config sets max_client_load=50, so the
 * first client-load chunk contains file-001.txt … file-050.txt (S3 lexicographic
 * order). The prefix "file-2" matches file-200.txt … file-250.txt — all of which
 * sort AFTER the first chunk, so client-side filtering returns nothing and the
 * "Search on server" affordance appears.
 */
import { test, expect } from "@playwright/test";
import { loginAsAdmin as login } from "./fixtures/auth-helpers";

const ROLE = process.env.E2E_MINIO_ROLE ?? "MinIO-e2e";
const BUCKET = process.env.E2E_MINIO_BUCKET ?? "e2e-test";

test.describe("Server-side prefix search via MinIO", () => {
  test("truncated folder shows affordance, server search loads target, exit restores folder", async ({
    page,
  }) => {
    await login(page);
    // Reuse the pagination folder: 250 objects, first chunk is file-001..file-050.
    await page.goto(`/v2/r/${ROLE}/b/${BUCKET}/p/pagination`);

    // Wait for the first chunk to render — same assertion as the pagination spec.
    await expect(
      page.locator("tr").filter({ hasText: "file-001.txt" }),
    ).toBeVisible({ timeout: 15_000 });

    // The folder is truncated (250 > max_client_load=50).
    await expect(page.getByText(/\+ objects/)).toBeVisible();

    // file-250.txt is past the first chunk — not loaded yet.
    await expect(
      page.locator("tr").filter({ hasText: "file-250.txt" }),
    ).toHaveCount(0);

    // Type a prefix that only matches objects beyond the first chunk.
    // "file-2" matches file-200…file-250 — none are in the 50-object first load.
    const searchInput = page.getByPlaceholder("Filter files…");
    await searchInput.fill("file-2");

    // The folder is truncated and a search term is typed, so the "Search on
    // server" affordance appears. The matching files (file-200..file-250) are
    // not in the first loaded chunk, so only the server search can surface them.
    const affordance = page.getByRole("button", {
      name: /Search "file-2" on server \(starts-with\)/,
    });
    await expect(affordance).toBeVisible({ timeout: 5_000 });

    // Clicking the affordance triggers a server prefix search.
    await affordance.click();

    // The server returns all items whose name starts with "file-2" in this folder.
    // file-200.txt should be visible without clicking "Load all".
    await expect(
      page.locator("tr").filter({ hasText: "file-200.txt" }),
    ).toBeVisible({ timeout: 15_000 });

    // The "Server search" chip must appear to indicate the mode.
    await expect(
      page.getByText("Server search (starts-with, case-sensitive):"),
    ).toBeVisible();

    // Exit server search via the CloseButton on the chip.
    await page.getByLabel("Exit server search").click();

    // Back to the normal folder view — first-chunk item is visible again.
    await expect(
      page.locator("tr").filter({ hasText: "file-001.txt" }),
    ).toBeVisible({ timeout: 10_000 });

    // The server search chip is gone.
    await expect(
      page.getByText("Server search (starts-with, case-sensitive):"),
    ).toHaveCount(0);
  });
});
