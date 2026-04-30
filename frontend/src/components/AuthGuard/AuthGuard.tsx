import { Center, Loader } from "@mantine/core";
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useMe } from "@/features/auth/hooks/useMe";
import { ApiError } from "@/utils/apiError";

// Gates protected routes. Behavior:
//   - loading → spinner (don't flash login page mid-fetch)
//   - 401     → redirect to /login (preserves intended URL via state.from)
//   - other error → bubble to ErrorBoundary
//   - success → render children via <Outlet />
export function AuthGuard() {
  const location = useLocation();
  const { data, isLoading, error } = useMe();

  if (isLoading) {
    return (
      <Center h="100vh">
        <Loader />
      </Center>
    );
  }

  if (error) {
    if (error instanceof ApiError && error.isAuthError()) {
      return <Navigate to="/login" replace state={{ from: location.pathname }} />;
    }
    throw error;
  }

  if (!data) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
