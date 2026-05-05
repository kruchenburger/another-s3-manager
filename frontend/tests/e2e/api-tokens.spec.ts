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
});
