import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { readFileSync } from "node:fs";

test.skip(!process.env.OIDC_E2E, "Requires the isolated fake OP CI lane");

async function start(page: import("@playwright/test").Page, subject: string) {
  await page.goto("/api/auth/oidc/login?return_to=/");
  await page.getByLabel("Fixture subject").fill(subject);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.waitForURL(
    (url) => url.hostname === "asm.oidc.test" && url.pathname === "/",
  );
}

test("test_cross_site_lax_callback_strict_session_after_interstitial", async ({
  page,
}) => {
  await page.request.post("/api/login", {
    form: { username: "admin", password: "FixturePassword1" },
  });
  let sawCallback = false;
  let sawTransaction = false;
  let sawOldSession = false;
  page.on("request", async (request) => {
    if (new URL(request.url()).pathname === "/api/auth/oidc/callback") {
      const cookie = (await request.allHeaders()).cookie ?? "";
      sawCallback = true;
      sawTransaction = cookie.includes("oidc_tx_");
      sawOldSession = cookie.includes("access_token=");
    }
  });
  await page.goto("/login");
  await start(page, "reader");
  expect(sawCallback).toBe(true);
  expect(sawTransaction).toBe(true);
  expect(sawOldSession).toBe(false);
  const me = await page.request.get("/api/me");
  expect(me.ok()).toBe(true);
  expect((await me.json()).username === "reader").toBe(true);
  const cookies = await page.context().cookies();
  expect(
    cookies.some(
      (cookie) =>
        cookie.name === "access_token" && cookie.sameSite === "Strict",
    ),
  ).toBe(true);
  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "best-practice"])
    .analyze();
  expect(
    result.violations.filter(
      (v) => v.impact === "critical" || v.impact === "serious",
    ).length,
  ).toBe(0);
});

for (const order of [
  [0, 1],
  [1, 0],
]) {
  test(`test_two_subjects_replace_one_cookie_jar_in_both_response_orders_${order.join("")}`, async ({
    context,
  }) => {
    const pages = [await context.newPage(), await context.newPage()];
    const subjects = [
      `subject-a-${order.join("")}`,
      `subject-b-${order.join("")}`,
    ];
    const releases: Array<() => void> = [];
    await context.route("**/api/auth/oidc/callback?**", async (route) => {
      const response = await route.fetch({ maxRedirects: 0 });
      const index = pages.indexOf(route.request().frame().page());
      await new Promise<void>((resolve) => {
        releases[index] = resolve;
      });
      await route.fulfill({ response });
    });
    const pending = pages.map((page, index) => start(page, subjects[index]));
    await expect.poll(() => releases.filter(Boolean).length).toBe(2);
    releases[order[0]]();
    await pending[order[0]];
    releases[order[1]]();
    await pending[order[1]];
    for (const page of pages) {
      await page.bringToFront();
      await page.evaluate(() => window.dispatchEvent(new Event("focus")));
      await expect
        .poll(
          async () =>
            (await (await page.request.get("/api/me")).json()).username ===
            subjects[order[1]],
        )
        .toBe(true);
      await expect(
        page.getByText(subjects[order[0]], { exact: true }),
      ).toHaveCount(0);
    }
  });
}

test("test_oidc_artifacts_contain_no_auth_material", async ({}, testInfo) => {
  expect(testInfo.project.use.trace === "off").toBe(true);
  expect(testInfo.project.use.video === "off").toBe(true);
  expect(testInfo.project.use.screenshot === "off").toBe(true);
  expect(testInfo.config.reporter.every(([name]) => name !== "html")).toBe(
    true,
  );
  const workflow = readFileSync("../.github/workflows/ci.yml", "utf8");
  const lane = workflow.split("  oidc-fake:")[1]?.split(/^  \S/m)[0] ?? "";
  expect(lane.includes("upload-artifact")).toBe(false);
  expect(lane.includes("run-oidc-e2e.sh")).toBe(true);
});
