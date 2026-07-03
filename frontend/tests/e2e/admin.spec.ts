import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./fixtures/auth-helpers";

test.describe("Admin pages", () => {
  test("admin can navigate to /admin/users via UserMenu", async ({
    page,
  }) => {
    await loginAsAdmin(page);
    await page.getByLabel("User menu").click();
    await page.getByRole("menuitem", { name: /admin console/i }).click();
    await expect(page).toHaveURL(/\/admin\/users$/);
    await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();
  });

  test("admin sidebar contains all four admin pages plus Back to files", async ({
    page,
  }) => {
    await loginAsAdmin(page);
    await page.goto("/admin/users");
    for (const label of ["Users", "Bans", "Roles", "Settings"]) {
      await expect(page.locator(`nav >> text=${label}`).first()).toBeVisible();
    }
    await expect(
      page.locator("nav >> text=Back to files").first(),
    ).toBeVisible();
  });

  test("legacy vanilla bookmark /admin redirects to /admin/users", async ({
    page,
  }) => {
    await loginAsAdmin(page);
    await page.goto("/admin");
    await expect(page).toHaveURL(/\/admin\/users$/);
    await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();
  });

  test("Back to files returns to /", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/admin/settings");
    await page.locator("nav >> text=Back to files").click();
    await expect(page).toHaveURL("/");
  });

  test("non-admin sees Forbidden on /admin/users", async () => {
    // Requires a seeded non-admin user. Phase 4c MinIO fixture seeds one;
    // until then, mark as fixme so the spec runs cleanly.
    test.fixme(true, "needs a seeded non-admin user — Phase 4c will provide");
  });
});
