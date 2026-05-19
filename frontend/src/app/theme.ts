import { Badge, Button, createTheme } from "@mantine/core";
import type { CSSVariablesResolver, MantineColorsTuple } from "@mantine/core";

// kruchenburger brand (per brand/DESIGN-SYSTEM.md in the parent workspace):
//   "bun"    = slate (every app shares this)
//   "amber"  = this app's accent (#F59E0B family — connotes storage / warmth)
// Primary color uses amber for CTAs (login, upload). slate is for surfaces, borders, text.
const slate: MantineColorsTuple = [
  "#f5f7fa", // 0
  "#e4e9f0", // 1
  "#cbd3df", // 2
  "#a9b4c4", // 3
  "#8794a8", // 4
  "#67748a", // 5
  "#4f5b70", // 6
  "#3b4658", // 7
  "#2a3343", // 8
  "#1a212e", // 9 — dark-mode body background
];

// Amber "cheese" — this app's signature accent (per brand book #F59E0B).
const amber: MantineColorsTuple = [
  "#fff8e1", // 0
  "#ffecb3", // 1
  "#ffe082", // 2
  "#ffd54f", // 3
  "#ffca28", // 4
  "#ffc107", // 5 — primary in dark mode
  "#ffb300", // 6 — primary in light mode
  "#ffa000", // 7
  "#ff8f00", // 8
  "#ff6f00", // 9
];

export const theme = createTheme({
  primaryColor: "amber",
  primaryShade: { light: 6, dark: 5 },

  fontFamily: "'DM Sans', system-ui, sans-serif",
  fontFamilyMonospace: "'JetBrains Mono', ui-monospace, monospace",
  defaultRadius: "md",

  colors: {
    slate,
    amber,
  },

  headings: {
    fontFamily: "'Space Grotesk', sans-serif",
    fontWeight: "600",
  },

  components: {
    // Scope autoContrast to the two components where filled-on-coloured-
    // background actually matters. A theme-wide autoContrast would also apply
    // to ActionIcon and a handful of other filled variants — fine in practice
    // because autoContrast only affects `variant="filled"` per Mantine 8 docs,
    // but being explicit here makes the intent visible at the call site and
    // immune to any future Mantine change that broadens autoContrast's reach.
    Button: Button.extend({ defaultProps: { size: "sm", radius: "md", autoContrast: true } }),
    Badge: Badge.extend({ defaultProps: { autoContrast: true } }),
    TextInput: { defaultProps: { size: "sm", radius: "md" } },
    PasswordInput: { defaultProps: { size: "sm", radius: "md" } },
    Select: { defaultProps: { size: "sm", radius: "md" } },
    Card: { defaultProps: { radius: "lg", padding: "lg", withBorder: true } },
    Modal: { defaultProps: { radius: "lg", centered: true } },
    Notification: { defaultProps: { radius: "md" } },
  },
});

/**
 * CSS variables resolver — values returned here win over Mantine's defaults
 * without the CSS-specificity dance we'd otherwise need in a separate
 * stylesheet (Mantine injects its own `:root[data-mantine-color-scheme=dark]`
 * declarations at specificity 0,2,0).
 *
 * Override rationale:
 *
 * `--mantine-color-dimmed` defaults to `var(--mantine-color-dark-2)` (#828282)
 * in dark mode, which fails WCAG 2.1 AA contrast: 4.03:1 against the standard
 * dark body background `#242424` (needs 4.5:1 for normal text). The token is
 * our standard for hint / helper / secondary text, so every page tripped on
 * the a11y baseline. `#969696` passes at 4.69:1 with no perceptible UI shift.
 *
 * Light mode's default (`#5c5f66` on `#ffffff` = 7.04:1) already passes, so
 * we don't touch the `light` map.
 */
export const cssVariablesResolver: CSSVariablesResolver = () => ({
  variables: {},
  light: {},
  dark: {
    "--mantine-color-dimmed": "#969696",
  },
});
