import { Outlet } from "react-router-dom";
import { AppShellLayout } from "@/components/AppShell/AppShellLayout";
import { AdminSidebar } from "./AdminSidebar";

/**
 * Same shell as the file browser, but the navbar slot is the admin nav
 * instead of the role/bucket tree.
 *
 * Pass <Outlet /> explicitly — admin pages don't share the spotlight-tour
 * context that AppShellLayout's default Outlet exposes via context, so
 * useOutletContext() inside admin routes will return undefined by design.
 */
export function AdminLayout() {
  return (
    <AppShellLayout navbar={<AdminSidebar />}>
      <Outlet />
    </AppShellLayout>
  );
}
