import { ActionIcon, useMantineColorScheme } from "@mantine/core";
import { Moon, Sun } from "lucide-react";

export function ThemeToggle() {
  const { colorScheme, toggleColorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";

  const handleToggle = () => {
    // Mantine sets `data-mantine-color-scheme` on <html> synchronously inside
    // toggleColorScheme, so wrapping it in a View Transition captures the
    // before/after frames and cross-fades the whole page over ~240ms (duration
    // set in global.css). This sidesteps the per-element CSS-transition problem:
    // Mantine briefly injects `transition: none` during the swap AND several of
    // its own components (AppShell, Title) override the global colour transition,
    // so a CSS-only approach snaps on the biggest surfaces. The View Transition
    // dissolves everything uniformly instead. Falls back to an instant switch
    // when the API is unavailable or the user prefers reduced motion.
    const prefersReducedMotion = window.matchMedia(
      "(prefers-reduced-motion: reduce)",
    ).matches;
    if (!prefersReducedMotion && typeof document.startViewTransition === "function") {
      document.startViewTransition(() => toggleColorScheme());
    } else {
      toggleColorScheme();
    }
  };

  return (
    <ActionIcon
      variant="subtle"
      color="gray"
      size="lg"
      onClick={handleToggle}
      aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
    >
      {isDark ? <Sun size={18} /> : <Moon size={18} />}
    </ActionIcon>
  );
}
