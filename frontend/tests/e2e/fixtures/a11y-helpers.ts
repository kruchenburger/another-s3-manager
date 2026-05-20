import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";

/**
 * Run axe-core against the current page and assert no critical/serious violations.
 *
 * `moderate` and `minor` violations are logged to the test output but do not
 * fail the test — they're useful signals but include a lot of debatable rules
 * (e.g. "landmark-unique") that aren't worth blocking CI on. The contract is:
 * if axe flags something `critical` or `serious`, the page is genuinely broken
 * for assistive tech and we fix the code, never the threshold.
 *
 * Tags: WCAG 2.0/2.1 levels A and AA plus axe's `best-practice` collection.
 * `wcag2a/aa` + `wcag21a/aa` cover the legally-relevant ruleset; `best-practice`
 * adds non-normative checks that catch real assistive-tech bugs (e.g. duplicate
 * landmarks, focus order).
 */
export async function expectNoSeriousAxeViolations(
  page: Page,
  scopeDescription: string,
): Promise<void> {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"])
    .analyze();

  const blocking = results.violations.filter(
    (v) => v.impact === "critical" || v.impact === "serious",
  );
  const informational = results.violations.filter(
    (v) => v.impact === "moderate" || v.impact === "minor",
  );

  if (informational.length > 0) {
    // eslint-disable-next-line no-console
    console.log(
      `[a11y][${scopeDescription}] ${informational.length} non-blocking violations:\n  ` +
        informational.map((v) => `${v.id} (${v.impact}): ${v.help}`).join("\n  "),
    );
  }

  expect(
    blocking,
    `[a11y][${scopeDescription}] critical/serious violations:\n` +
      blocking
        .map(
          (v) =>
            `  ${v.id} (${v.impact}): ${v.help}\n    nodes: ${v.nodes.length}\n    ${v.nodes
              .slice(0, 3)
              .map((n) => n.target.join(" "))
              .join("\n    ")}`,
        )
        .join("\n"),
  ).toEqual([]);
}
