import type { ReactNode } from "react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClientProvider } from "@tanstack/react-query";
import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";
import { theme } from "@/app/theme";
import { queryClient } from "@/app/queryClient";

interface AppProvidersProps {
  children: ReactNode;
}

// Single composition point so tests + Storybook can wrap children identically.
// Order matters: QueryClient outer (so providers can use queries),
// Mantine inner (so theme is available everywhere).
export function AppProviders({ children }: AppProvidersProps) {
  return (
    <QueryClientProvider client={queryClient}>
      <MantineProvider theme={theme} defaultColorScheme="dark">
        <Notifications position="bottom-right" />
        {children}
      </MantineProvider>
    </QueryClientProvider>
  );
}
