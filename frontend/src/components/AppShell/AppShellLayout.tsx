import { AppShell } from "@mantine/core";
import { Outlet } from "react-router-dom";
import { AppHeader } from "@/components/AppShell/AppHeader";

export function AppShellLayout() {
  return (
    <AppShell header={{ height: 60 }} padding="md">
      <AppShell.Header>
        <AppHeader />
      </AppShell.Header>
      <AppShell.Main>
        <Outlet />
      </AppShell.Main>
    </AppShell>
  );
}
