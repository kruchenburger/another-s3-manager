import { test, expect } from "@playwright/test";

const ADMIN_USER = process.env.E2E_ADMIN_USERNAME ?? "admin";
const ADMIN_PASSWORD =
  process.env.E2E_ADMIN_PASSWORD ??
  process.env.ADMIN_PASSWORD ??
  "test-admin-pw-12345";

async function loginAsAdmin(page: import("@playwright/test").Page) {
  await page.goto("/v2/login");
  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password").fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Login" }).click();
  // URL may be /v2 or /v2/ depending on router
  await expect(page).toHaveURL(/\/v2\/?$/);
}

test.describe("Admin pages", () => {
  test("admin can navigate to /v2/admin/users via UserMenu", async ({
    page,
  }) => {
    await loginAsAdmin(page);
    await page.getByLabel("User menu").click();
    await page.getByRole("menuitem", { name: /admin console/i }).click();
    await expect(page).toHaveURL(/\/v2\/admin\/users$/);
    await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();
  });

  test("admin sidebar contains all four admin pages plus Back to files", async ({
    page,
  }) => {
    await loginAsAdmin(page);
    await page.goto("/v2/admin/users");
    for (const label of ["Users", "Bans", "Roles", "Settings"]) {
      await expect(page.locator(`nav >> text=${label}`).first()).toBeVisible();
    }
    await expect(
      page.locator("nav >> text=Back to files").first(),
    ).toBeVisible();
  });

  test("Back to files returns to /v2/", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/v2/admin/settings");
    await page.locator("nav >> text=Back to files").click();
    await expect(page).toHaveURL(/\/v2\/?$/);
  });

  test("non-admin sees Forbidden on /v2/admin/users", async () => {
    // Requires a seeded non-admin user. Phase 4c MinIO fixture seeds one;
    // until then, mark as fixme so the spec runs cleanly.
    test.fixme(true, "needs a seeded non-admin user — Phase 4c will provide");
  });
});
