import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useMe } from "@/features/auth/hooks/useMe";

/**
 * Forces the user to complete a password change before accessing any route
 * other than /change-password itself. Triggered when admin creates a user
 * with the "Require password change" checkbox (default) or resets their
 * password with the same checkbox. Cleared by PUT /api/me/password.
 *
 * Sits inside AuthGuard so unauthenticated users are still bounced to /login
 * first. Wraps both the regular shell and the admin shell.
 */
export function RequireFreshPassword() {
  const { data: me } = useMe();
  const location = useLocation();

  // While me is loading, render the outlet — AuthGuard already ensures we
  // have a session; flickering a redirect to /change-password before me
  // arrives would be wrong. The guard only acts on confirmed data.
  if (me?.must_change_password && location.pathname !== "/change-password") {
    return <Navigate to="/change-password" replace />;
  }

  return <Outlet />;
}
