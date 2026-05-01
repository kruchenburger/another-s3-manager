import { test, expect } from "@playwright/test";

const ADMIN_USER = "admin";
const ADMIN_PASS = process.env.ADMIN_PASSWORD ?? "test-admin-pw-12345";

test.beforeEach(async ({ page }) => {
  await page.goto("/v2/login");
  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password").fill(ADMIN_PASS);
  await page.getByRole("button", { name: "Login" }).click();
  // URL may be /v2 or /v2/ depending on router
  await expect(page).toHaveURL(/\/v2\/?$/);
});

test("home page shows empty state for admin with no roles", async ({ page }) => {
  // Default admin user has no allowed_roles set, so home shows empty state
  await expect(page.getByText(/Pick a role/i).first()).toBeVisible();
});

// Note: more navigation tests require a configured role + bucket. The default
// dev `.env` doesn't seed any. In Phase 4 we'll add a test fixture role.
// For now, this baseline confirms login + home + empty state render correctly.
