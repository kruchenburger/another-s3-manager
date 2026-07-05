// frontend/src/app/ThemePreviewProvider.tsx
import { MantineProvider } from "@mantine/core";
import type { ReactNode } from "react";
import { mutedSlateBlueTheme, cssVariablesResolver } from "./theme";

interface Props {
  children: ReactNode;
}

/**
 * MantineProvider wrapper. Phase 6b shipped a floating
 * DevThemeSwitcher behind this component for A/B-ing between four
 * palettes before user smoke-testing settled on Muted Slate-Blue;
 * the switcher (and the themeVariants module it lazy-loaded) is gone
 * now that the palette is locked.
 *
 * The component is kept as a thin wrapper so callers stay decoupled
 * from MantineProvider details — if we ever need another global
 * UI-tree decorator (color-scheme toggle, density toggle, …) it
 * lives here.
 */
export function ThemePreviewProvider({ children }: Props) {
  return (
    <MantineProvider
      theme={mutedSlateBlueTheme}
      defaultColorScheme="dark"
      cssVariablesResolver={cssVariablesResolver}
    >
      {children}
    </MantineProvider>
  );
}
