import { test } from "@playwright/test";
import { expectNoSeriousAxeViolations } from "./fixtures/a11y-helpers";
import { loginAsAdmin } from "./fixtures/auth-helpers";

/**
 * Accessibility baseline — see docs/accessibility.md.
 *
 * Walks every covered route in / (login + post-login + admin) and asserts
 * no critical/serious axe-core violations. Designed to keep the bar high
 * (catches real assistive-tech blockers) without drowning in subjective rule
 * complaints. Add new routes here with a fresh `test(...)` block.
 */
test.describe("a11y baseline", () => {
  test("login page", async ({ page }) => {
    await page.goto("/login");
    await expectNoSeriousAxeViolations(page, "/login");
  });

  test("home (after login)", async ({ page }) => {
    await loginAsAdmin(page);
    await expectNoSeriousAxeViolations(page, "/");
  });

  test("change password page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/change-password");
    await expectNoSeriousAxeViolations(page, "/change-password");
  });

  test("api tokens (self-serve) page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/api-tokens");
    await expectNoSeriousAxeViolations(page, "/api-tokens");
  });

  test("admin users page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/admin/users");
    await expectNoSeriousAxeViolations(page, "/admin/users");
  });

  test("admin bans page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/admin/bans");
    await expectNoSeriousAxeViolations(page, "/admin/bans");
  });

  test("admin settings page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/admin/settings");
    await expectNoSeriousAxeViolations(page, "/admin/settings");
  });

  test("admin roles page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/admin/roles");
    await expectNoSeriousAxeViolations(page, "/admin/roles");
  });

  test("admin role new page (3-step wizard)", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/admin/roles/new");
    await expectNoSeriousAxeViolations(page, "/admin/roles/new");
  });

  test("admin api tokens page", async ({ page }) => {
    await loginAsAdmin(page);
    await page.goto("/admin/api-tokens");
    await expectNoSeriousAxeViolations(page, "/admin/api-tokens");
  });
});
