import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./fixtures/auth-helpers";

test.beforeEach(async ({ page }) => {
  await loginAsAdmin(page);
});

test("home page shows empty state for admin with no roles", async ({ page }) => {
  // Default admin user has no allowed_roles set, so home shows empty state
  await expect(page.getByText(/Pick a role/i).first()).toBeVisible();
});

// Note: more navigation tests require a configured role + bucket. The default
// dev `.env` doesn't seed any. In Phase 4 we'll add a test fixture role.
// For now, this baseline confirms login + home + empty state render correctly.
