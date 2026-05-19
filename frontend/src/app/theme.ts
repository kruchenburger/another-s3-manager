import { createTheme } from "@mantine/core";

// kruchenburger brand (per D:\kruchenburger\brand\DESIGN-SYSTEM.md):
//   "bun"    = slate (every app shares this)
//   "amber"  = this app's accent (#F59E0B family — connotes storage / warmth)
// Primary color uses amber for CTAs (login, upload). slate is for surfaces, borders, text.
export const theme = createTheme({
  primaryColor: "amber",
  primaryShade: { light: 6, dark: 5 },

  // Ask Mantine to pick a high-contrast text colour for filled buttons /
  // badges / etc. on the basis of the background's luminance, instead of the
  // hard-coded white that ships by default. Our amber primary (#ffc107 in
  // dark mode) is too light for white text — contrast falls to 1.63:1, well
  // under WCAG AA 4.5:1. With autoContrast Mantine flips the text to near-
  // black on bright amber and to white on dark colours like red/green.
  autoContrast: true,

  fontFamily: "'DM Sans', system-ui, sans-serif",
  fontFamilyMonospace: "'JetBrains Mono', ui-monospace, monospace",
  defaultRadius: "md",

  colors: {
    // Slate "bun" — neutral surfaces, header, borders. Shared across kruchenburger.
    slate: [
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
    ],
    // Amber "cheese" — this app's signature accent (per brand book #F59E0B).
    amber: [
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
    ],
  },

  headings: {
    fontFamily: "'Space Grotesk', sans-serif",
    fontWeight: "600",
  },

  components: {
    Button: { defaultProps: { size: "sm", radius: "md" } },
    TextInput: { defaultProps: { size: "sm", radius: "md" } },
    PasswordInput: { defaultProps: { size: "sm", radius: "md" } },
    Select: { defaultProps: { size: "sm", radius: "md" } },
    Card: { defaultProps: { radius: "lg", padding: "lg", withBorder: true } },
    Modal: { defaultProps: { radius: "lg", centered: true } },
    Notification: { defaultProps: { radius: "md" } },
  },
});
