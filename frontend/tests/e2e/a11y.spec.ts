import { test, expect } from "@playwright/test";
import { expectNoSeriousAxeViolations } from "./fixtures/a11y-helpers";

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
  await expect(page).toHaveURL(/\/v2\/?$/);
}

/**
 * Accessibility baseline — see docs/accessibility.md.
 *
 * Walks every authenticated route and asserts no critical/serious axe-core
 * violations. Designed to keep the bar high (catches real assistive-tech
 * blockers) without drowning in subjective rule complaints.
 *
 * If a future page is added, register it here with a `test(...)` block.
 */
test.describe("a11y baseline", () => {
  test("login page", async ({ page }) => {
    await page.goto("/v2/login");
    await expectNoSeriousAxeViolations(page, "/v2/login");
  });

  test("home (after login)", async ({ page }) => {
    await loginAsAdmin(page);
    await expectNoSeriousAxeViolations(page, "/v2/");
  });

  test("change password page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/v2/change-password");
    await expectNoSeriousAxeViolations(page, "/v2/change-password");
  });

  test("api tokens (self-serve) page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/v2/api-tokens");
    await expectNoSeriousAxeViolations(page, "/v2/api-tokens");
  });

  test("admin users page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/v2/admin/users");
    await expectNoSeriousAxeViolations(page, "/v2/admin/users");
  });

  test("admin bans page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/v2/admin/bans");
    await expectNoSeriousAxeViolations(page, "/v2/admin/bans");
  });

  test("admin settings page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/v2/admin/settings");
    await expectNoSeriousAxeViolations(page, "/v2/admin/settings");
  });

  test("admin roles page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/v2/admin/roles");
    await expectNoSeriousAxeViolations(page, "/v2/admin/roles");
  });

  test("admin role new page (3-step wizard)", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/v2/admin/roles/new");
    await expectNoSeriousAxeViolations(page, "/v2/admin/roles/new");
  });

  test("admin api tokens page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/v2/admin/api-tokens");
    await expectNoSeriousAxeViolations(page, "/v2/admin/api-tokens");
  });
});
