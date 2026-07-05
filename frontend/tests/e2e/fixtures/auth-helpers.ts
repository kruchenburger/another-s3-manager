import { expect } from "@playwright/test";
import type { Page } from "@playwright/test";

/**
 * Shared credentials + login helper for E2E specs.
 *
 * Single source of truth — previously each spec duplicated the same constants
 * with three different fallback patterns and two different default passwords,
 * so a tweak to the CI env contract risked silently bypassing one of them.
 *
 * Precedence: `E2E_ADMIN_PASSWORD` wins (CI sets this, see ci.yml). If absent
 * we fall back to legacy `ADMIN_PASSWORD` for backward compat with anyone
 * sourcing their `.env` locally — and finally to the policy-compliant
 * `TestPass1` used by the CI workflow + MinIO-flavoured specs.
 */
export const ADMIN_USER = process.env.E2E_ADMIN_USERNAME ?? "admin";
export const ADMIN_PASSWORD =
  process.env.E2E_ADMIN_PASSWORD ?? process.env.ADMIN_PASSWORD ?? "TestPass1";

/**
 * Log in as admin and assert the authenticated shell rendered.
 *
 * The URL check alone is misleading on failure: a wrong password or dropped
 * cookie leaves the browser on `/login`, so Playwright reports "expected
 * /?$ but got /login" without telling you that the credentials were
 * never accepted. The follow-up element check confirms the AppShell mounted —
 * if the user menu button is present, the auth cookie was set and the React
 * router moved past the login route.
 */
export async function loginAsAdmin(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill(ADMIN_USER);
  // exact: true — Mantine 9 PasswordInput renders a "Toggle password visibility"
  // button whose aria-label also contains "password", so a substring getByLabel
  // match resolves to 2 elements. Anchor to the input's exact "Password" label.
  await page.getByLabel("Password", { exact: true }).fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Login" }).click();
  // Successful login lands on /, which HomePage immediately auto-redirects
  // to /r/<role>/... for any user with roles (default_role or first role).
  // Asserting the transient / URL is a race the warm local backend loses —
  // assert we LEFT the login route instead; the user-menu check below is what
  // proves the authenticated shell actually mounted.
  await expect(page).not.toHaveURL(/\/login/);
  // AppShell rendered → login actually succeeded. Without this, every
  // downstream assertion fails with a misleading "element not found" instead
  // of a clear "you never logged in".
  await expect(page.getByLabel("User menu")).toBeVisible();
}
