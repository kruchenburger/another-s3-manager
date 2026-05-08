import { Outlet } from "react-router-dom";
import { AppShellLayout } from "@/components/AppShell/AppShellLayout";
import { AdminSidebar } from "./AdminSidebar";

/**
 * Same shell as the file browser, but the navbar slot is the admin nav
 * instead of the role/bucket tree.
 */
export function AdminLayout() {
  return (
    <AppShellLayout navbar={<AdminSidebar />} forceExpanded>
      <Outlet />
    </AppShellLayout>
  );
}
