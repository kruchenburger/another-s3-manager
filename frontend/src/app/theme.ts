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

// Airify (spec rev 2): slate-tinted dark palette derived from the Claude
// Design mockup. Index mapping in the dark scheme (per Mantine 9 docs):
// 0 text · 2 dimmed · 3 placeholder · 4 default-border (solid fallback;
// the CSS var is overridden to translucent white in cssVariablesResolver)
// · 5 default-hover/chip · 6 default bg (inputs, zebra stripe) · 7 body
// (also Paper/Card/Modal — elevated surfaces re-tinted via --as3m-surface)
// · 8 panel · 9 code.
export const dark: MantineColorsTuple = [
  "#e7ecf3", // 0 — mockup --text
  "#c3cddb", // 1
  "#9aa5b4", // 2 — mockup --ink-dim (6.47:1 on body, 5.68:1 on surface)
  "#6b7585", // 3 — mockup --ink-mute
  "#353d4d", // 4 — solid ≈ white 8.5% over surface
  "#2a3343", // 5 — mockup --chip
  "#222b3c", // 6 — mockup --surface
  "#1a212e", // 7 — mockup --bg (matches login slate-9 at last)
  "#161b24", // 8 — mockup --panel
  "#0b0e14", // 9 — mockup --code-bg
];

// Elevated-surface color in dark scheme — single source for the resolver's
// --as3m-surface and the contrast guard test (tests/unit/themeContrast.test.ts).
export const SURFACE_DARK = "#222b3c";

// Primary filled-hover per scheme. The mockup's dark hover LIGHTENS
// (its #6d8cb6), but white 13px button text on that is 3.45:1 — a real
// axe serious violation whenever the button is hovered. #57759b keeps the
// lighten-on-hover idiom at 4.75:1. Guarded by themeContrast.test.ts.
export const PRIMARY_HOVER_DARK = "#57759b";
export const PRIMARY_HOVER_LIGHT = "#52719a";

// Mockup semantic families (Full scope), each anchored at index 6 — the
// shade filled variants use (primaryShade {light:6, dark:6} applies to all
// colors, not just the primary).
export const coralRed: MantineColorsTuple = [
  "#fdf1f0",
  "#fbe0dd",
  "#f6c3be",
  "#f0a29a",
  "#ef7f74",
  "#ec6154", // 5 — dark-scheme error text (4.93:1 on body)
  "#e8493f", // 6 — mockup --danger (dark)
  "#e0463d", // 7 — mockup --danger (light)
  "#c93a32", // 8 — light-scheme error text (4.74:1 on light body)
  "#a92e28",
];

export const sageGreen: MantineColorsTuple = [
  "#f0f9f3",
  "#dcf0e2",
  "#c0e2cc",
  "#a3d4b4",
  "#8dcaa2",
  "#83c598",
  "#79c08f", // 6 — mockup --ok
  "#63a97a",
  "#4f9166",
  "#3c7752",
];

export const gold: MantineColorsTuple = [
  "#fbf5e9",
  "#f6ead1",
  "#eed9ae",
  "#e6c78b",
  "#dfb66f",
  "#dbae62",
  "#d8a657", // 6 — mockup --mid
  "#c08f3f",
  "#a3762f",
  "#855e24",
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

// Amber stays registered for legacy `color="amber"` call-sites, but airify
// re-tunes it to the mockup gold family so there is ONE gold everywhere
// (same values as `gold`, which also overrides orange/yellow).
export const amber: MantineColorsTuple = [
  "#fbf5e9",
  "#f6ead1",
  "#eed9ae",
  "#e6c78b",
  "#dfb66f",
  "#dbae62",
  "#d8a657",
  "#c08f3f",
  "#a3762f",
  "#855e24",
];

// Shared component defaults across the app.
const sharedComponents = {
  Button: Button.extend({
    defaultProps: { size: "sm", radius: "md", autoContrast: true },
  }),
  Badge: Badge.extend({ defaultProps: { autoContrast: true } }),
  TextInput: { defaultProps: { size: "sm", radius: "md" } },
  PasswordInput: { defaultProps: { size: "sm", radius: "md" } },
  Select: { defaultProps: { size: "sm", radius: "md" } },
  Card: { defaultProps: { radius: 12, padding: "lg", withBorder: true } }, // airify: mockup card radius 12px, roomier padding
  Modal: {
    defaultProps: {
      radius: 12,
      centered: true,
      closeButtonProps: { "aria-label": "Close" },
    },
  },
  Drawer: {
    defaultProps: { closeButtonProps: { "aria-label": "Close" } },
  },
  // Mantine 9 dropped the built-in "Close" aria-label on the CloseButton that
  // Modal/Drawer/Popover render internally, so every dismiss ✕ was a critical
  // axe `button-name` violation. Restore it at the source — covers standalone
  // CloseButton usages too, not just the Modal/Drawer cases above.
  CloseButton: { defaultProps: { "aria-label": "Close" } },
  Notification: { defaultProps: { radius: "md" } },
  Table: { defaultProps: { verticalSpacing: "sm", horizontalSpacing: "sm" } }, // airify: more air (FileTable pins xs — virtualized)
};

// Shared typography — tighter "tool-feel" scale from spec §3.2.
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

// Production theme — Muted Slate-Blue. This is what ships; Phase 6b's
// dev theme switcher (which let developers A/B between palettes during
// smoke testing) was removed once the palette was locked.
export const mutedSlateBlueTheme = createTheme({
  ...sharedTypography,
  primaryColor: "mutedSlateBlue",
  primaryShade: { light: 6, dark: 6 }, // see spec §3.1.1 — WCAG fix
  colors: {
    slate,
    mutedSlateBlue,
    // Keep amber registered as a secondary palette so legacy
    // `color="amber"` usages (warning ThemeIcons, error Alerts, etc.)
    // still resolve to a real CSS variable instead of falling back to
    // grey (values re-tuned to the airify gold family).
    amber,
    // Airify overrides: slate-layered dark surfaces + mockup semantics.
    // Registering under the built-in names recolors every call-site
    // (color="red"/"green"/"orange"/"yellow") with zero JSX edits.
    dark,
    red: coralRed,
    green: sageGreen,
    orange: gold,
    yellow: gold,
  },
  components: sharedComponents,
});

// CSS variables resolver — airify (spec rev 2):
// - dimmed: mockup ink-dim #9aa5b4 (AA: 6.47:1 body / 5.68:1 surface;
//   guarded by tests/unit/themeContrast.test.ts).
// - default-border: the mockup's translucent white hairline in dark —
//   the single biggest "air" contributor. Table/Divider borders follow it.
// - error: Mantine's OWN defaults (red.8-on-dark, red.6-on-light) sit
//   below 4.5:1 on our bodies; pin the shades that pass.
// - primary filled hover: mockup hover LIGHTENS in dark (#6d8cb6);
//   Mantine's default darkens.
// - --as3m-*: custom tokens for layered surfaces + shadows, consumed by
//   global.css and the chrome CSS modules (sidebar/header/bulk bar).
//   Panel/header stay translucent because both keep backdrop blur(12px)
//   glass; composited over the new body they land on the mockup's
//   #161b24 / #1b2331.
export const cssVariablesResolver: CSSVariablesResolver = () => ({
  variables: {},
  light: {
    "--mantine-color-body": "#f5f7fa",
    "--mantine-color-default-border": "#e4e9f0",
    "--mantine-color-error": "var(--mantine-color-red-8)",
    "--mantine-primary-color-filled-hover": PRIMARY_HOVER_LIGHT,
    "--as3m-surface": "#ffffff",
    "--as3m-panel": "rgba(255, 255, 255, 0.85)",
    "--as3m-header": "rgba(255, 255, 255, 0.92)",
    "--as3m-shadow-rest": "0 1px 3px rgba(40, 55, 80, 0.08)",
    "--as3m-shadow-float": "0 14px 32px rgba(40, 55, 80, 0.16)",
  },
  dark: {
    "--mantine-color-dimmed": "#9aa5b4",
    "--mantine-color-default-border": "rgba(255, 255, 255, 0.085)",
    "--mantine-color-error": "var(--mantine-color-red-5)",
    "--mantine-primary-color-filled-hover": PRIMARY_HOVER_DARK,
    "--as3m-surface": SURFACE_DARK,
    "--as3m-panel": "rgba(22, 27, 36, 0.72)",
    "--as3m-header": "rgba(27, 35, 49, 0.72)",
    "--as3m-shadow-rest": "0 1px 4px rgba(0, 0, 0, 0.25)",
    "--as3m-shadow-float": "0 14px 38px rgba(0, 0, 0, 0.5)",
  },
});
