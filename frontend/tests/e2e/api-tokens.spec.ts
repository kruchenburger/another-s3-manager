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

test.describe("API tokens self-serve flow", () => {
  test("create token, see plaintext, revoke", async ({ page }) => {
    await loginAsAdmin(page);

    // Navigate to /v2/api-tokens via UserMenu
    await page.getByLabel("User menu").click();
    await page.getByRole("menuitem", { name: /api tokens/i }).click();
    await expect(page).toHaveURL(/\/v2\/api-tokens$/);

    // Open Create token modal
    await page.getByRole("button", { name: /create token/i }).click();

    // Fill the name field with a unique name
    const tokenName = `e2e-${Date.now()}`;
    await page.getByLabel("Name").fill(tokenName);

    // Submit the form — button text is "Create" (inside the modal)
    await page.getByRole("dialog").getByRole("button", { name: /^create$/i }).click();

    // TokenPlaintextModal: Alert title contains "will not be shown again"
    await expect(
      page.getByText(/will not be shown again/i),
    ).toBeVisible({ timeout: 5_000 });

    // The token is rendered in a <Code block> element — check the as3m_ prefix
    const tokenLocator = page.locator("code").first();
    const tokenText = await tokenLocator.textContent();
    expect(tokenText).toMatch(/^as3m_/);

    // Dismiss the plaintext modal via "I copied the token — close" button
    await page.getByRole("button", { name: /i copied the token/i }).click();

    // Token row must appear in the table; last_used_at=null renders as "never"
    const row = page.locator("tr").filter({ hasText: tokenName });
    await expect(row).toBeVisible({ timeout: 5_000 });
    await expect(row.getByText("never")).toBeVisible();

    // Revoke via the per-row Trash icon (aria-label="Revoke <name>")
    await row.getByRole("button", { name: `Revoke ${tokenName}` }).click();

    // ConfirmDeleteModal: click the red "Delete" button to confirm
    await page.getByRole("dialog").getByRole("button", { name: /^delete$/i }).click();

    // Row disappears after successful deletion
    await expect(row).not.toBeVisible({ timeout: 5_000 });
  });

  test("edits an existing token without re-issuing plaintext", async ({ page }) => {
    await loginAsAdmin(page);

    await page.getByLabel("User menu").click();
    await page.getByRole("menuitem", { name: /api tokens|mcp tokens/i }).click();
    await expect(page).toHaveURL(/\/v2\/api-tokens$/);

    // Create a token to edit
    const initialName = `e2e-edit-${Date.now()}`;
    await page.getByRole("button", { name: /create token/i }).click();
    await page.getByLabel("Name").fill(initialName);
    await page.getByRole("dialog").getByRole("button", { name: /^create$/i }).click();

    // Dismiss the plaintext modal
    await expect(
      page.getByText(/will not be shown again/i),
    ).toBeVisible({ timeout: 5_000 });
    await page.getByRole("button", { name: /i copied the token/i }).click();

    // Open edit modal via the per-row Pencil icon
    const row = page.locator("tr").filter({ hasText: initialName });
    await expect(row).toBeVisible({ timeout: 5_000 });
    await row.getByRole("button", { name: `Edit ${initialName}` }).click();

    // Rename and save
    const renamed = `${initialName}-renamed`;
    const editDialog = page.getByRole("dialog");
    await editDialog.getByLabel("Name").fill(renamed);
    await editDialog.getByRole("button", { name: /^save$/i }).click();

    // Listing reflects the new name; plaintext modal must NOT re-appear
    await expect(page.locator("tr").filter({ hasText: renamed })).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.getByText(/will not be shown again/i)).not.toBeVisible();

    // Cleanup: revoke the renamed token
    const renamedRow = page.locator("tr").filter({ hasText: renamed });
    await renamedRow.getByRole("button", { name: `Revoke ${renamed}` }).click();
    await page.getByRole("dialog").getByRole("button", { name: /^delete$/i }).click();
  });

  test("admin issuing token via UserDrawer shows plaintext exactly once", async ({
    page,
  }) => {
    // Regression guard: PR #20 review caught that UserTokensList silently
    // discarded the plaintext from the create response. This walks the full
    // flow from /v2/admin/users → drawer → "Issue token on behalf" → assert
    // the plaintext modal appears.
    await loginAsAdmin(page);
    await page.goto("/v2/admin/users");

    // Open the first user's edit drawer (the admin user always exists).
    await page.locator("tbody tr").first().getByLabel(/edit/i).click();
    await expect(page.getByRole("dialog")).toBeVisible({ timeout: 5_000 });

    // Scroll to and click "Issue token on behalf" inside the drawer's
    // UserTokensList section.
    const drawer = page.getByRole("dialog");
    await drawer
      .getByRole("button", { name: /issue token on behalf/i })
      .click();

    // CreateTokenModal opens (separate dialog). Fill name and submit.
    const onBehalfName = `e2e-on-behalf-${Date.now()}`;
    const createDialog = page
      .getByRole("dialog")
      .filter({ hasText: /create mcp token/i });
    await createDialog.getByLabel("Name").fill(onBehalfName);
    await createDialog.getByRole("button", { name: /^create$/i }).click();

    // The plaintext modal must appear with the secret. Without the fix,
    // the create modal closed silently and no secret was ever shown.
    await expect(
      page.getByText(/this token will not be shown again/i),
    ).toBeVisible({ timeout: 5_000 });
    const plaintextLocator = page.locator("code").first();
    const plaintextText = await plaintextLocator.textContent();
    expect(plaintextText).toMatch(/^as3m_/);

    // Dismiss
    await page
      .getByRole("button", { name: /i copied the token/i })
      .click();

    // Cleanup: the new token now lives under the admin user. Revoke it via
    // the admin tokens page (the user drawer scopes to the original user we
    // opened, but the on-behalf payload's user_id may differ depending on
    // which row was first).
    await page.goto("/v2/admin/api-tokens");
    const newRow = page.locator("tr").filter({ hasText: onBehalfName });
    if (await newRow.isVisible()) {
      await newRow
        .getByRole("button", { name: `Revoke ${onBehalfName}` })
        .click();
      await page
        .getByRole("dialog")
        .getByRole("button", { name: /^delete$/i })
        .click();
    }
  });
});
