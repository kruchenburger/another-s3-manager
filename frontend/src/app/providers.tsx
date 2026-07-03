import type { ReactNode } from "react";
import { Notifications } from "@mantine/notifications";
import { QueryClientProvider } from "@tanstack/react-query";
import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import "@/app/global.css";
import { ThemePreviewProvider } from "@/app/ThemePreviewProvider";
import { queryClient } from "@/app/queryClient";

interface AppProvidersProps {
  children: ReactNode;
}

// Single composition point so tests + Storybook can wrap children identically.
// Order matters: QueryClient outer (so providers can use queries),
// Mantine inner (so theme is available everywhere). ThemePreviewProvider wraps
// MantineProvider and in dev exposes a floating theme switcher widget.
export function AppProviders({ children }: AppProvidersProps) {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemePreviewProvider>
        {/* Bottom toast stacks are lifted to bottom: 80px (see global.css) so
            they clear the floating scroll-to-top button and the admin Settings
            Save bar. The lift MUST live in CSS scoped to [data-position^="bottom"]
            — the `style` prop is copied by Mantine onto ALL six per-position
            root containers, so it stretched the top-* ones (top:16 + bottom:80)
            across half the viewport, where they silently swallowed clicks. */}
        {/* limit caps simultaneously visible toasts. Bulk operations must
            still aggregate their errors (a huge queue would drip-feed
            replacements for minutes even with a limit). */}
        <Notifications position="bottom-right" limit={5} />
        {children}
      </ThemePreviewProvider>
    </QueryClientProvider>
  );
}
