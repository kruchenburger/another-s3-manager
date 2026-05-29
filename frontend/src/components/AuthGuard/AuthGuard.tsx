import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useMe } from "@/features/auth/hooks/useMe";
import { ApiError } from "@/utils/apiError";
import { DelayedLoader } from "@/components/DelayedLoader/DelayedLoader";

// Gates protected routes. Behavior:
//   - loading → DelayedLoader (Mantine spinner after 500ms)
//   - 401     → redirect to /login
//   - other error → bubble to ErrorBoundary
//   - success → render children via <Outlet />
export function AuthGuard() {
  const location = useLocation();
  const { data, isLoading, error } = useMe();

  if (isLoading) {
    return <DelayedLoader />;
  }

  if (error) {
    if (error instanceof ApiError && error.isAuthError()) {
      return (
        <Navigate to="/login" replace state={{ from: location.pathname }} />
      );
    }
    throw error;
  }

  if (!data) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
