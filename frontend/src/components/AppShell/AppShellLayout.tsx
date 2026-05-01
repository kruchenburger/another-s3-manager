import { useState } from "react";
import { AppShell } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Outlet } from "react-router-dom";
import { AppHeader } from "@/components/AppShell/AppHeader";
import { Sidebar } from "@/components/Sidebar/Sidebar";

const COLLAPSED_KEY = "sidebar:collapsed";

export function AppShellLayout() {
  const [navOpened, { toggle: toggleNav, close: closeNav }] = useDisclosure(false);
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    return localStorage.getItem(COLLAPSED_KEY) === "true";
  });

  const toggleCollapsed = () => {
    setCollapsed((c) => {
      const next = !c;
      localStorage.setItem(COLLAPSED_KEY, String(next));
      return next;
    });
  };

  // Tour state hoisted here so HelpButton (header) and Sidebar's `?` both open it
  const [tourOpen, setTourOpen] = useState(false);
  const openTour = () => setTourOpen(true);

  return (
    <AppShell
      header={{ height: 60 }}
      navbar={{
        width: collapsed ? 60 : 260,
        breakpoint: "sm",
        collapsed: { mobile: !navOpened },
      }}
      padding="md"
    >
      <AppShell.Header
        style={{
          background: "light-dark(rgba(255, 255, 255, 0.6), rgba(26, 33, 46, 0.6))",
          backdropFilter: "blur(12px)",
          WebkitBackdropFilter: "blur(12px)",
        }}
      >
        <AppHeader navOpened={navOpened} onNavToggle={toggleNav} onOpenTour={openTour} />
      </AppShell.Header>
      <AppShell.Navbar p={0}>
        <Sidebar
          collapsed={collapsed}
          onToggleCollapsed={toggleCollapsed}
          onOpenTour={openTour}
        />
      </AppShell.Navbar>
      <AppShell.Main onClick={closeNav}>
        <Outlet context={{ tourOpen, setTourOpen }} />
      </AppShell.Main>
    </AppShell>
  );
}
