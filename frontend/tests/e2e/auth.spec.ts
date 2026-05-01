import { test, expect } from "@playwright/test";

const ADMIN_USER = "admin";
const ADMIN_PASS = process.env.ADMIN_PASSWORD ?? "test-admin-pw-12345";

test("login and logout flow", async ({ page }) => {
  // Visit /v2/, expect redirect to /v2/login
  await page.goto("/v2/");
  await expect(page).toHaveURL(/\/v2\/login/);

  // Fill and submit login form
  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password").fill(ADMIN_PASS);
  await page.getByRole("button", { name: "Login" }).click();

  // Land on home, see Welcome (URL may be /v2 or /v2/ depending on router)
  await expect(page).toHaveURL(/\/v2\/?$/);

  // Open user menu and logout
  await page.getByLabel("User menu").click();
  await page.getByRole("menuitem", { name: /Logout/i }).click();

  // Back at login
  await expect(page).toHaveURL(/\/v2\/login/);
});

test("invalid credentials show error", async ({ page }) => {
  await page.goto("/v2/login");
  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password").fill("wrong-password");
  await page.getByRole("button", { name: "Login" }).click();

  // Stay on login, see alert
  await expect(page).toHaveURL(/\/v2\/login/);
  await expect(page.getByText(/Incorrect username or password/i)).toBeVisible();
});
