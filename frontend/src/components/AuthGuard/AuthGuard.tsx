import { useEffect } from "react";
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { notifications } from "@mantine/notifications";
import { useMe } from "@/features/auth/hooks/useMe";
import { ApiError } from "@/utils/apiError";
import { DelayedLoader } from "@/components/DelayedLoader/DelayedLoader";
import { useSessionIdentity } from "@/features/auth/hooks/useSessionIdentity";
import { safeReturnTo } from "@/features/auth/utils/safeReturnTo";

export const SESSION_ENDED_NOTIFICATION_ID = "session-ended";

// Redirects to sign-in. When the user was signed in a moment ago (the /api/me data is
// still cached), the session expired or was ended on the server, so say so instead of
// silently swapping the page for the login form.
function SignInRedirect({
  from,
  sessionEnded,
}: {
  from: string;
  sessionEnded: boolean;
}) {
  useEffect(() => {
    if (!sessionEnded) return;
    notifications.show({
      id: SESSION_ENDED_NOTIFICATION_ID,
      color: "yellow",
      title: "Session ended",
      message: "Your session expired or was ended. Sign in again to continue.",
      // Stays until dismissed: the redirect already moved the user, a 4 s corner toast is easy to miss.
      autoClose: false,
    });
  }, [sessionEnded]);

  return <Navigate to="/login" replace state={{ from }} />;
}

// Gates protected routes. Behavior:
//   - loading → DelayedLoader (Mantine spinner after 500ms)
//   - 401     → redirect to /login (with a "Session ended" notice if the user was signed in)
//   - other error → bubble to ErrorBoundary
//   - success → render children via <Outlet />
export function AuthGuard() {
  const location = useLocation();
  const { blocked } = useSessionIdentity();
  const { data, isLoading, error } = useMe();

  // A valid session again (after signing back in) retires the "Session ended" notice,
  // which otherwise stays until dismissed.
  const sessionValid = data !== undefined && !error;
  useEffect(() => {
    if (sessionValid) notifications.hide(SESSION_ENDED_NOTIFICATION_ID);
  }, [sessionValid]);

  if (isLoading || blocked) {
    return <DelayedLoader />;
  }

  if (error) {
    if (error instanceof ApiError && error.isAuthError()) {
      return (
        <SignInRedirect
          from={safeReturnTo(location.pathname + location.search)}
          sessionEnded={data !== undefined}
        />
      );
    }
    throw error;
  }

  if (!data) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
