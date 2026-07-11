import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { ADMIN_USER, ADMIN_PASSWORD } from "./fixtures/auth-helpers";

/**
 * E2E against a local AWS emulator (ministack: S3 + IAM + STS).
 *
 * This exercises the four AWS-native role paths that a MinIO-only backend can't
 * cover end-to-end:
 *   1. `assume_role` — the app mints temporary STS credentials and browses the
 *      seeded bucket. The app's STS client carries no explicit endpoint, so CI
 *      sets `AWS_ENDPOINT_URL_STS=http://localhost:4566` to redirect AssumeRole
 *      at ministack with NO backend code change.
 *   2. `credentials` — a role configured with a direct access-key/secret pair
 *      (minted by the seed for the `restricted` IAM user) browses the same
 *      seeded bucket. Proves the minted keys + direct-credentials path work
 *      end-to-end.
 *   3. `profile` — a role that resolves credentials from a named AWS profile in
 *      `AWS_SHARED_CREDENTIALS_FILE`. CI writes a credentials file pointing at
 *      ministack and names it `ministack-profile`, proving the profile-lookup
 *      path reaches the emulator end-to-end.
 *   4. `default` — a role that uses the default credential chain (env
 *      credentials); the S3 endpoint comes from the role's `endpoint_url`.
 *      Proves the app's fallback path works when no explicit credential source
 *      is configured on the role.
 *
 * IAM ENFORCEMENT IS INTENTIONALLY NOT TESTED. A verification spike proved this
 * ministack image accepts IAM policies but does NOT enforce them on S3 — a
 * "deny → 403 on the forbidden bucket" assertion would be testing emulator
 * behaviour we know is absent, so that test was deliberately dropped. The seed
 * still writes the scoped policy to document intent, but it is not a boundary
 * here. A 2026-06-12 spike confirmed LocalStack community doesn't enforce S3 IAM
 * either, so deny→403 stays a real-AWS smoke check (see docs/testing-backends.md).
 * See scripts/ci/seed_ministack.py for the provisioned roles/buckets.
 *
 * Roles/buckets are env-parameterized but default to the seed's names.
 *
 * NOTE on login: we can't reuse the shared `loginAsAdmin` helper here. That
 * helper asserts the post-login URL is exactly `/`, which holds only for an
 * admin with no roles (the MinIO CI fixture). The ministack seed's roles ARE
 * admin-accessible, so HomePage auto-redirects to the default role's bucket and
 * the URL is never `/`. We log in with the same canonical selectors and
 * assert success via the "User menu" button (the same robust signal the helper
 * uses internally), then navigate explicitly — independent of where the
 * post-login redirect lands.
 */

const ASSUME_ROLE = process.env.E2E_MINISTACK_ASSUME_ROLE ?? "ministack-assume";
const CREDS_ROLE = process.env.E2E_MINISTACK_CREDS_ROLE ?? "ministack-creds";
const PROFILE_ROLE = process.env.E2E_MINISTACK_PROFILE_ROLE ?? "ministack-profile";
const DEFAULT_ROLE = process.env.E2E_MINISTACK_DEFAULT_ROLE ?? "ministack-default";
const ALLOWED = process.env.E2E_MINISTACK_ALLOWED_BUCKET ?? "ministack-allowed";

async function login(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill(ADMIN_USER);
  await page.getByLabel("Password", { exact: true }).fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  // AppShell rendered → auth cookie set + router moved past /login. We don't
  // assert a specific URL: with admin-accessible roles, HomePage redirects to
  // the default role/bucket, so the landing URL is intentionally not /.
  await expect(page.getByLabel("User menu")).toBeVisible({ timeout: 15_000 });
}

async function browseBucket(page: Page, role: string, bucket: string): Promise<void> {
  // Real route from frontend/src/app/router.tsx: /r/:roleId/b/:bucket.
  await page.goto(`/r/${role}/b/${bucket}`);
  // File table is the main listing UI; wait for it before asserting the row.
  await page.locator("table").waitFor();
  // Seeded object proves the S3 round-trip reached the bucket.
  await expect(page.locator("tr").filter({ hasText: "hello.txt" })).toBeVisible({
    timeout: 20_000,
  });
}

test.describe("ministack AWS-native backend", () => {
  test("assume_role: STS-backed role browses the seeded bucket", async ({ page }) => {
    await login(page);
    await browseBucket(page, ASSUME_ROLE, ALLOWED);
  });

  test("credentials: direct-key role browses the seeded bucket", async ({ page }) => {
    await login(page);
    await browseBucket(page, CREDS_ROLE, ALLOWED);
  });

  test("profile: named AWS-profile role browses the seeded bucket", async ({ page }) => {
    await login(page);
    await browseBucket(page, PROFILE_ROLE, ALLOWED);
  });

  test("default: default-credential-chain role browses the seeded bucket", async ({ page }) => {
    await login(page);
    await browseBucket(page, DEFAULT_ROLE, ALLOWED);
  });
});
