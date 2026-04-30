import { createTheme } from "@mantine/core";

// kruchenburger brand:
//   "bun"    = slate (every app shares this)
//   "cheese" = amber (this app's accent — connotes storage / archive / honey)
// Primary color uses cheese for CTAs (login, upload). slate is reserved for
// neutrals, surfaces, borders.
export const theme = createTheme({
  primaryColor: "cheese",
  primaryShade: { light: 6, dark: 5 },
  fontFamily: "Inter, system-ui, sans-serif",
  fontFamilyMonospace: "JetBrains Mono, ui-monospace, monospace",
  defaultRadius: "md",

  colors: {
    // Slate "bun" — neutral surfaces, header, borders. Shared across kruchenburger apps.
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
      "#1a212e", // 9
    ],
    // Amber "cheese" — this app's signature accent. Buttons, links, focus rings.
    cheese: [
      "#fff8e1", // 0
      "#ffecb3", // 1
      "#ffe082", // 2
      "#ffd54f", // 3
      "#ffca28", // 4
      "#ffc107", // 5
      "#ffb300", // 6 — primary in light mode
      "#ffa000", // 7
      "#ff8f00", // 8
      "#ff6f00", // 9
    ],
  },

  headings: {
    fontFamily: "Inter, system-ui, sans-serif",
    fontWeight: "600",
  },

  components: {
    Button: { defaultProps: { size: "sm", radius: "md" } },
    TextInput: { defaultProps: { size: "sm", radius: "md" } },
    PasswordInput: { defaultProps: { size: "sm", radius: "md" } },
    Select: { defaultProps: { size: "sm", radius: "md" } },
    Card: { defaultProps: { radius: "md", padding: "lg", withBorder: true } },
    Modal: { defaultProps: { radius: "md", centered: true } },
    Notification: { defaultProps: { radius: "md" } },
  },
});
