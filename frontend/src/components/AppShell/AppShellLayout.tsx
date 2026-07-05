import { useEffect, useState } from "react";
import { AppShell } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Outlet, useLocation } from "react-router-dom";
import { AppHeader } from "@/components/AppShell/AppHeader";
import { Sidebar } from "@/components/Sidebar/Sidebar";

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

export function AppShellLayout({
  children,
  navbar,
  forceExpanded = false,
}: AppShellLayoutProps = {}) {
  const [navOpened, { toggle: toggleNav, close: closeNav }] = useDisclosure(false);
  const location = useLocation();

  // Mobile UX: the burger nav is a full-width overlay below sm — after
  // picking a role/bucket it used to stay open, hiding the very content the
  // user just navigated to (they had to close it by hand). Auto-close on
  // every route change; desktop is unaffected (the navbar there is
  // persistent, `collapsed.mobile` only applies below the breakpoint).
  useEffect(() => {
    closeNav();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);
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
          background: "var(--as3m-header)",
          backdropFilter: "blur(12px)",
          WebkitBackdropFilter: "blur(12px)",
        }}
      >
        <AppHeader navOpened={navOpened} onNavToggle={toggleNav} />
      </AppShell.Header>
      <AppShell.Navbar p={0}>
        {navbar ?? <Sidebar collapsed={collapsed} onToggleCollapsed={toggleCollapsed} />}
      </AppShell.Navbar>
      <AppShell.Main onClick={closeNav}>{children ?? <Outlet />}</AppShell.Main>
    </AppShell>
  );
}
