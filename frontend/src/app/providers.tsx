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
        <Notifications position="bottom-right" />
        {children}
      </ThemePreviewProvider>
    </QueryClientProvider>
  );
}
