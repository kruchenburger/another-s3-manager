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
    const owners = new WeakMap<import("@playwright/test").Request, number>();
    let stopping = false;
    // Playwright does not route requests that arrive through a redirect, and the
    // ASM callback is reached by the OP's 302. Gate the OP consent submission that
    // answers with that 302 instead: releasing it lets exactly one tab proceed to
    // its callback, so the release order is the callback-response order.
    const callback = (url: URL) =>
      url.hostname === "op.identity.test" &&
      url.pathname === "/authorize" &&
      url.searchParams.has("fixture_subject");
    pages.forEach((page, index) => {
      // Request events identify the tab even when a navigation has no frame yet.
      page.on("request", (request) => owners.set(request, index));
    });
    const handler = async (route: import("@playwright/test").Route) => {
      if (stopping) {
        await route.abort();
        return;
      }
      const request = route.request();
      let index = owners.get(request);
      if (index === undefined) {
        try {
          index = pages.indexOf(request.frame().page());
        } catch {
          // The request event remains the primary navigation ownership seam.
        }
      }
      if (index === undefined || index < 0) {
        await route.abort();
        throw new Error(
          "OIDC callback could not be associated with a test tab",
        );
      }
      await new Promise<void>((resolve) => {
        releases[index] = resolve;
      });
      await route.continue();
    };
    await context.route(callback, handler);
    const pending = pages.map((page, index) =>
      start(page, subjects[index]).then(
        () => true,
        () => false,
      ),
    );
    try {
      await expect
        .poll(() => releases.filter(Boolean).length, {
          timeout: 15_000,
          message:
            "Both OIDC consent submissions must reach the release barrier",
        })
        .toBe(2);
      releases[order[0]]();
      expect(
        await pending[order[0]],
        "First released OIDC navigation completes",
      ).toBe(true);
      releases[order[1]]();
      expect(
        await pending[order[1]],
        "Last released OIDC navigation completes",
      ).toBe(true);
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
    } finally {
      stopping = true;
      releases.forEach((release) => release());
      await context.unroute(callback, handler);
      await Promise.all(pending);
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
