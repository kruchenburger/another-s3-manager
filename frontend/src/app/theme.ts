import { Badge, Button, createTheme, rem } from "@mantine/core";
import type { CSSVariablesResolver, MantineColorsTuple } from "@mantine/core";

// kruchenburger brand: "bun" = slate (every app shares this neutral surface palette).
// another-s3-manager Phase 6b accent: Muted Slate-Blue #5E7FA8 (replaces amber).
export const slate: MantineColorsTuple = [
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

// Muted Slate-Blue — Phase 6b primary accent (see spec §3.1 for derivation).
export const mutedSlateBlue: MantineColorsTuple = [
  "#f1f4f8", // 0
  "#dde5ee", // 1
  "#bccada", // 2 — borders, dividers, sidebar-active text on dark
  "#97acc4", // 3 — focus-ring outline
  "#7591b3", // 4
  "#5E7FA8", // 5 — primary text-tone / sidebar-active rail / accent border
  "#4f6b8f", // 6 — primary fill (dark mode AND light mode, see §3.1.1)
  "#405876", // 7
  "#324663", // 8
  "#243349", // 9
];

// Amber retained ONLY for the dev switcher's pre-Phase-6b baseline comparison.
// Production primaryColor switches off amber in Task 9; until then, amber stays
// the active production palette so Tasks 3-8 ride into prod risk-free.
export const amber: MantineColorsTuple = [
  "#fff8e1", // 0
  "#ffecb3", // 1
  "#ffe082", // 2
  "#ffd54f", // 3
  "#ffca28", // 4
  "#ffc107", // 5
  "#ffb300", // 6
  "#ffa000", // 7
  "#ff8f00", // 8
  "#ff6f00", // 9
];

// Shared component defaults — applied to every theme variant so dev-switching
// only changes colours, not spacing/typography.
const sharedComponents = {
  Button: Button.extend({
    defaultProps: { size: "sm", radius: "md", autoContrast: true },
  }),
  Badge: Badge.extend({ defaultProps: { autoContrast: true } }),
  TextInput: { defaultProps: { size: "sm", radius: "md" } },
  PasswordInput: { defaultProps: { size: "sm", radius: "md" } },
  Select: { defaultProps: { size: "sm", radius: "md" } },
  Card: { defaultProps: { radius: "lg", padding: "md", withBorder: true } }, // padding lg → md (density B)
  Modal: { defaultProps: { radius: "lg", centered: true } },
  Notification: { defaultProps: { radius: "md" } },
  Table: { defaultProps: { verticalSpacing: "xs", horizontalSpacing: "sm" } }, // density B
};

// Shared typography — tighter "tool-feel" scale from spec §3.2.
// Applied via theme so every dev-switcher variant inherits.
const sharedTypography = {
  fontFamily: "'DM Sans', system-ui, sans-serif",
  fontFamilyMonospace: "'JetBrains Mono', ui-monospace, monospace",
  defaultRadius: "md",
  // Keep Mantine's default 14px body — the 13px scale from the spec
  // shrank everything too aggressively. Title size still bumped via
  // headings.sizes.h3 below.
  fontSizes: {
    xs: rem(12),
    sm: rem(13),
    md: rem(14),
    lg: rem(16),
    xl: rem(18),
  },
  headings: {
    fontFamily: "'Space Grotesk', sans-serif",
    fontWeight: "600",
    sizes: {
      h1: { fontSize: rem(24), lineHeight: "1.2", fontWeight: "600" },
      h2: { fontSize: rem(20), lineHeight: "1.2", fontWeight: "600" },
      h3: { fontSize: rem(18), lineHeight: "1.2", fontWeight: "600" }, // page title
      h4: { fontSize: rem(15), lineHeight: "1.3", fontWeight: "600" },
      h5: { fontSize: rem(14), lineHeight: "1.4", fontWeight: "600" },
      h6: { fontSize: rem(14), lineHeight: "1.4", fontWeight: "600" }, // not smaller than body
    },
  },
  // "auto" = focus ring only on keyboard navigation (not mouse click).
  // "always" was draw the ring on every focus event including mouse
  // clicks, which looked like a stuck highlight on Tab tabs + ActionIcons.
  focusRing: "auto" as const,
};

// Phase 6b target theme — Muted Slate-Blue. Becomes the production default
// in Task 9 (the "color flip" commit). Until then, end users see the amber
// theme below; ThemePreviewProvider lets developers switch in dev only.
export const mutedSlateBlueTheme = createTheme({
  ...sharedTypography,
  primaryColor: "mutedSlateBlue",
  primaryShade: { light: 6, dark: 6 }, // see spec §3.1.1 — WCAG fix
  colors: {
    slate,
    mutedSlateBlue,
    // Keep amber registered in the production muted theme so legacy
    // `color="amber"` usages (Avatars, ThemeIcons, error/warn Buttons,
    // role-type palette helper, ResetPasswordModal) still resolve to a
    // real CSS variable instead of falling back to grey. We only changed
    // the primary palette in Phase 6b — secondary amber tokens stay as
    // accent options across the app.
    amber,
  },
  components: sharedComponents,
});

// Production-default amber theme — kept in theme.ts (not themeVariants.ts)
// so it ships in the prod bundle. Name deliberately avoids the string
// "amberBaselineTheme" because check-prod-bundle.sh forbids that exact
// identifier from leaking from the dev-only switcher's grep allowlist.
// Task 9 swaps this out by changing ThemePreviewProvider.PRODUCTION_DEFAULT
// from "amber" to "muted" — that's the only end-user-visible commit.
export const productionAmberTheme = createTheme({
  ...sharedTypography,
  primaryColor: "amber",
  primaryShade: { light: 6, dark: 5 }, // original amber shade from pre-Phase-6b
  colors: {
    slate,
    amber,
  },
  components: sharedComponents,
});

// Legacy backwards-compat re-export so any consumer that imported { theme } still works.
// Phase 6b: still points at amber until Task 9.
export const theme = productionAmberTheme;

// CSS variables resolver — unchanged from pre-Phase-6b, but now applies to all
// variants (the dev switcher injects the same resolver regardless of variant).
// Override rationale: --mantine-color-dimmed default fails WCAG AA on dark
// (#828282 on #1a212e = 4.03:1, needs 4.5:1). #969696 passes at 4.69:1.
export const cssVariablesResolver: CSSVariablesResolver = () => ({
  variables: {},
  light: {},
  dark: {
    "--mantine-color-dimmed": "#969696",
  },
});
