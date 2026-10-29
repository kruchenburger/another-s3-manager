import { test, expect, type Page } from "@playwright/test";
import { loginAsAdmin as login } from "./fixtures/auth-helpers";

const ROLE = process.env.E2E_MINIO_ROLE ?? "MinIO-e2e";
const BUCKET = process.env.E2E_MINIO_BUCKET ?? "e2e-test";
const BASE = `/r/${encodeURIComponent(ROLE)}/b/${encodeURIComponent(BUCKET)}`;
const SUCCESS =
  "Move complete. The objects are at the destination and the originals were removed.";

function folderUrl(path: string) {
  return `${BASE}/p/${path.split("/").map(encodeURIComponent).join("/")}`;
}

function row(page: Page, name: string) {
  return page.getByRole("row").filter({
    has: page.getByRole("checkbox", { name: `Select ${name}`, exact: true }),
  });
}

async function createFolder(page: Page, name: string) {
  await page.getByRole("button", { name: "New folder", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "New folder", exact: true });
  await dialog.getByLabel("Folder name", { exact: true }).fill(name);
  await dialog.getByRole("button", { name: "Create folder" }).click();
  await expect(dialog).not.toBeVisible();
}

async function expectNoRename(page: Page) {
  for (const role of ["button", "menuitem", "link"] as const) {
    await expect(
      page.getByRole(role, { name: "Rename", exact: true }),
    ).toHaveCount(0);
  }
}

test("folder creation, dialog moves, new names and row drag-and-drop via MinIO", async ({
  page,
}) => {
  test.setTimeout(120_000);
  const root = `folder-ops-${Date.now()}`;
  const jobs: string[] = [];
  let firstUpload = true;
  await login(page);

  async function upload(name: string) {
    // Exercise the first-upload hint; subsequent uploads open the chooser directly.
    const chooserPromise = page.waitForEvent("filechooser");
    await page.getByRole("button", { name: "Upload", exact: true }).click();
    if (firstUpload) {
      await page
        .getByRole("dialog", { name: "Upload files", exact: true })
        .getByRole("button", { name: "Choose files" })
        .click();
      firstUpload = false;
    }
    const chooser = await chooserPromise;
    await chooser.setFiles({
      name,
      mimeType: "text/plain",
      buffer: Buffer.from("folder move test"),
    });
    await expect(row(page, name)).toBeVisible({ timeout: 15_000 });
  }

  async function confirmMove(expectedCount: number) {
    const dialog = page.getByRole("dialog", {
      name: "Confirm move",
      exact: true,
    });
    await expect(dialog).toContainText(
      "Object storage has no rename or move. ASM copies each object to the new location and then deletes the original.",
    );
    await expect(dialog).toContainText(`This moves ${expectedCount} objects (`);
    if (expectedCount === 1) await expect(dialog).toContainText("(16 B)");
    const started = page.waitForResponse(
      (response) =>
        response.request().method() === "POST" &&
        new URL(response.url()).pathname ===
          `/api/buckets/${encodeURIComponent(BUCKET)}/move`,
    );
    await dialog.getByRole("button", { name: "Start move" }).click();
    const response = await started;
    expect(response.status()).toBe(202);
    const { job_id } = (await response.json()) as { job_id: string };
    jobs.push(job_id);
    await expect(dialog).not.toBeVisible();
    // A persistent progress panel, unlike the toast, cannot disappear before this assertion.
    const progress = page.getByLabel("Move jobs").getByRole("status");
    await expect(progress).toContainText(SUCCESS, { timeout: 20_000 });
    await expect(progress).toContainText(
      `Originals removed: ${expectedCount} / ${expectedCount}`,
    );
    await progress.getByRole("button", { name: "Dismiss move result" }).click();
    await expect(progress).toHaveCount(0);
  }

  try {
    await page.goto(BASE);
    await createFolder(page, root);
    // Root may be beyond the first 50 entries in CI. Never drain seeded fixtures.
    await page.goto(folderUrl(root));
    await expect(
      page.getByText("This folder is empty", { exact: true }),
    ).toBeVisible();
    await expectNoRename(page);

    await createFolder(page, "source");
    await expect(row(page, "source")).toBeVisible();
    await row(page, "source").getByText("source", { exact: true }).click();
    await expect(page).toHaveURL(folderUrl(`${root}/source`));
    await expect(
      page.getByText("This folder is empty", { exact: true }),
    ).toBeVisible();
    await upload("dialog.txt");

    await row(page, "dialog.txt").hover();
    await row(page, "dialog.txt")
      .getByRole("button", { name: "Move to…", exact: true })
      .click();
    const picker = page.getByRole("dialog", { name: "Move to…", exact: true });
    await expectNoRename(page);
    await picker.getByRole("button", { name: root, exact: true }).click();
    // Create the destination through the nested picker modal.
    await picker
      .getByRole("button", { name: "New folder", exact: true })
      .click();
    const newFolder = page.getByRole("dialog", {
      name: "New folder",
      exact: true,
    });
    await newFolder.getByLabel("Folder name", { exact: true }).fill("target");
    await newFolder.getByRole("button", { name: "Create folder" }).click();
    await expect(newFolder).not.toBeVisible();
    await picker
      .getByRole("button", { name: "Open folder target", exact: true })
      .click();
    await picker
      .getByRole("button", { name: "Move here", exact: true })
      .click();
    await confirmMove(1);
    await expect(row(page, "dialog.txt")).toHaveCount(0);
    await expect(
      page.getByText("This folder is empty", { exact: true }),
    ).toBeVisible();
    await page.goto(folderUrl(root));
    await expect(row(page, "source")).toBeVisible();
    await row(page, "target").getByText("target", { exact: true }).click();
    await expect(row(page, "dialog.txt")).toBeVisible();

    await page.goto(folderUrl(root));
    await createFolder(page, "old-name");
    await row(page, "old-name").getByText("old-name", { exact: true }).click();
    await upload("nested.txt");
    await page.goto(folderUrl(root));
    await row(page, "old-name").hover();
    await row(page, "old-name")
      .getByRole("button", { name: "Move to…", exact: true })
      .click();
    await picker.getByLabel("New name", { exact: true }).fill("new-name");
    await picker
      .getByRole("button", { name: "Move here", exact: true })
      .click();
    // The explicit folder marker and its nested file are both S3 objects.
    await confirmMove(2);
    await expect(row(page, "old-name")).toHaveCount(0);
    await expect(row(page, "new-name")).toBeVisible();
    await row(page, "new-name").getByText("new-name", { exact: true }).click();
    await expect(row(page, "nested.txt")).toBeVisible();

    // Open the compact actions menu as well as checking desktop actions and the picker.
    await page.setViewportSize({ width: 640, height: 900 });
    await row(page, "nested.txt")
      .getByRole("button", { name: "Actions for nested.txt", exact: true })
      .click();
    await expect(
      page.getByRole("menuitem", { name: "Move to…", exact: true }),
    ).toBeVisible();
    await expectNoRename(page);
    await page.keyboard.press("Escape");
    await page.setViewportSize({ width: 1280, height: 900 });

    await page.goto(folderUrl(root));
    await upload("drag.txt");
    await expect(row(page, "drag.txt")).toHaveAttribute("draggable", "true");
    await row(page, "drag.txt").dragTo(row(page, "target"));
    await confirmMove(1);
    await expect(row(page, "drag.txt")).toHaveCount(0);
    await row(page, "target").getByText("target", { exact: true }).click();
    await expect(row(page, "drag.txt")).toBeVisible();
    await expect(row(page, "dialog.txt")).toBeVisible();
  } finally {
    // Wait for reservations to clear even if a UI assertion failed after starting a job.
    for (const id of jobs) {
      await expect
        .poll(
          async () => {
            const response = await page.request.get(
              `/api/jobs/${encodeURIComponent(id)}`,
            );
            expect(response.ok()).toBeTruthy();
            const job = (await response.json()) as { state: string };
            return job.state;
          },
          { timeout: 20_000 },
        )
        .not.toBe("running");
    }
    // Delete only this test's prefix via cookie + CSRF, independent of root pagination or open modals.
    const me = await page.request.get("/api/me");
    expect(me.ok()).toBeTruthy();
    const { csrf_token } = (await me.json()) as { csrf_token: string };
    const params = new URLSearchParams({ role: ROLE, path: `${root}/` });
    const deleted = await page.request.delete(
      `/api/buckets/${encodeURIComponent(BUCKET)}/files?${params}`,
      { headers: { "X-CSRF-Token": csrf_token } },
    );
    expect(
      deleted.ok(),
      "Remove the isolated folder-operations fixture",
    ).toBeTruthy();
    const remaining = await page.request.get(
      `/api/buckets/${encodeURIComponent(BUCKET)}/files?${new URLSearchParams({ role: ROLE, client_load: "1", search: root })}`,
    );
    expect(remaining.ok()).toBeTruthy();
    const listing = (await remaining.json()) as {
      directories: unknown[];
      files: unknown[];
    };
    expect(listing.directories).toEqual([]);
    expect(listing.files).toEqual([]);
  }
});
