import { useState } from "react";
import { AppShell } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Outlet } from "react-router-dom";
import { AppHeader } from "@/components/AppShell/AppHeader";
import { Sidebar } from "@/components/Sidebar/Sidebar";
import { WelcomeToast } from "@/components/Onboarding/WelcomeToast";
import { SpotlightTour } from "@/components/Onboarding/SpotlightTour";

const COLLAPSED_KEY = "sidebar:collapsed";

interface AppShellLayoutProps {
  /** Render slot for the main area. Falls back to React Router's <Outlet /> when omitted. */
  children?: React.ReactNode;
  /** Navbar slot. Defaults to the file-browser <Sidebar />; admin shell overrides this. */
  navbar?: React.ReactNode;
  /**
   * When true, the navbar is locked to the expanded width (260px) regardless of
   * the persisted collapse preference. Used by the admin shell where there is
   * no role/bucket tree to collapse and the AdminSidebar always renders labels.
   */
  forceExpanded?: boolean;
}

export function AppShellLayout({ children, navbar, forceExpanded = false }: AppShellLayoutProps = {}) {
  const [navOpened, { toggle: toggleNav, close: closeNav }] = useDisclosure(false);
  const [collapsedPref, setCollapsedPref] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    return localStorage.getItem(COLLAPSED_KEY) === "true";
  });
  const collapsed = forceExpanded ? false : collapsedPref;

  const toggleCollapsed = () => {
    // Honour the JSDoc contract on `forceExpanded`: when the navbar is locked
    // expanded, neither the runtime state nor the persisted preference may
    // change. Today the toggle is unreachable from the admin shell (AdminSidebar
    // doesn't receive it), but guarding here prevents future refactors from
    // silently corrupting the file-browser sidebar's persisted state.
    if (forceExpanded) return;
    setCollapsedPref((c) => {
      const next = !c;
      localStorage.setItem(COLLAPSED_KEY, String(next));
      return next;
    });
  };

  // Tour state hoisted here so HelpButton (header) and WelcomeToast both open it.
  // Sidebar no longer hosts a tour entry — the only persistent UI control is
  // the HelpButton in the header.
  const [tourOpen, setTourOpen] = useState(false);
  const openTour = () => setTourOpen(true);

  return (
    <>
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
          {navbar ?? (
            <Sidebar collapsed={collapsed} onToggleCollapsed={toggleCollapsed} />
          )}
        </AppShell.Navbar>
        <AppShell.Main onClick={closeNav}>
          {children ?? <Outlet context={{ tourOpen, setTourOpen }} />}
        </AppShell.Main>
      </AppShell>
      <WelcomeToast onOpenTour={() => setTourOpen(true)} />
      <SpotlightTour open={tourOpen} onClose={() => setTourOpen(false)} />
    </>
  );
}
