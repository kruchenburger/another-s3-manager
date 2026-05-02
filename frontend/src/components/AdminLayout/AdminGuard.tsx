import { Outlet } from "react-router-dom";
import { useMe } from "@/features/auth/hooks/useMe";
import { ForbiddenPage } from "@/pages/ForbiddenPage";

/**
 * Renders the nested route only when the current user is an admin.
 * AuthGuard is assumed to have already loaded `me` (parent route).
 */
export function AdminGuard() {
  const { data: me, isLoading } = useMe();
  if (isLoading) return null;
  if (!me?.is_admin) return <ForbiddenPage />;
  return <Outlet />;
}
