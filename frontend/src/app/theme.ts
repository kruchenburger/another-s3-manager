import { createTheme } from "@mantine/core";

export const theme = createTheme({
  primaryColor: "brand",
  fontFamily: "Inter, system-ui, sans-serif",
  fontFamilyMonospace: "JetBrains Mono, monospace",
  defaultRadius: "md",

  colors: {
    brand: [
      "#f0f4ff", // 0 — lightest
      "#d9e2ff", // 1
      "#b1c3ff", // 2
      "#849fff", // 3
      "#5c7cff", // 4
      "#3b5bdb", // 5 — primary (filled buttons, links)
      "#3049b5", // 6
      "#253990", // 7
      "#1b2a6b", // 8
      "#111c47", // 9 — darkest
    ],
  },

  headings: {
    fontFamily: "Inter, system-ui, sans-serif",
    fontWeight: "600",
  },

  components: {
    Button: {
      defaultProps: { size: "sm", radius: "md" },
    },
    TextInput: {
      defaultProps: { size: "sm", radius: "md" },
    },
    Select: {
      defaultProps: { size: "sm", radius: "md" },
    },
    Card: {
      defaultProps: { radius: "md", padding: "lg", withBorder: true },
    },
    Modal: {
      defaultProps: { radius: "md", centered: true },
    },
    Notification: {
      defaultProps: { radius: "md" },
    },
  },
});
