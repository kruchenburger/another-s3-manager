import { test } from "@playwright/test";
import { expectNoSeriousAxeViolations } from "./fixtures/a11y-helpers";
import { loginAsAdmin } from "./fixtures/auth-helpers";

/**
 * Accessibility baseline — see docs/accessibility.md.
 *
 * Walks every covered route in /v2/ (login + post-login + admin) and asserts
 * no critical/serious axe-core violations. Designed to keep the bar high
 * (catches real assistive-tech blockers) without drowning in subjective rule
 * complaints. Add new routes here with a fresh `test(...)` block.
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
