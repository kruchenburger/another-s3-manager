import { test, expect } from "@playwright/test";
import { ADMIN_USER, ADMIN_PASSWORD as ADMIN_PASS } from "./fixtures/auth-helpers";

test("login and logout flow", async ({ page }) => {
  // Visit /, expect redirect to /login
  await page.goto("/");
  await expect(page).toHaveURL(/\/login/);

  // Fill and submit login form
  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password", { exact: true }).fill(ADMIN_PASS);
  await page.getByRole("button", { name: "Login" }).click();

  // Land on home, see Welcome (root URL)
  await expect(page).toHaveURL("/");

  // Open user menu and logout
  await page.getByLabel("User menu").click();
  await page.getByRole("menuitem", { name: /Logout/i }).click();

  // Back at login
  await expect(page).toHaveURL(/\/login/);
});

test("invalid credentials show error", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password", { exact: true }).fill("wrong-password");
  await page.getByRole("button", { name: "Login" }).click();

  // Stay on login, see alert
  await expect(page).toHaveURL(/\/login/);
  await expect(page.getByText(/Incorrect username or password/i)).toBeVisible();
});
