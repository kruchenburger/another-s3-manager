import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { EmptyState } from "@/components/EmptyState/EmptyState";
import { useMe } from "@/features/auth/hooks/useMe";

export function HomePage() {
  const { data: me, error } = useMe();
  const navigate = useNavigate();

  // Auto-open the role page when the user has exactly one accessible role —
  // the only-role-pickable list is degenerate. `replace: true` so Back from
  // the role page returns to login instead of bouncing through this empty
  // picker. Mirrors the single-bucket auto-redirect in RolePage.
  //
  // The `!error` guard mirrors RolePage (commit cf47557): TanStack Query can
  // hand back stale `me.allowed_roles` (length 1) while a fresh /api/me fails
  // (e.g. cookie expired, or role removed server-side after an admin save
  // invalidates the me query). Without this guard the effect would silently
  // navigate past the error path that AuthGuard / ErrorBoundary should show.
  useEffect(() => {
    if (!error && me && me.allowed_roles.length === 1) {
      navigate(`/r/${encodeURIComponent(me.allowed_roles[0]!)}`, { replace: true });
    }
  }, [me, navigate, error]);

  // Single-role users redirect via the effect above; render nothing in the
  // same tick so the picker doesn't flash before navigation. Mirror the
  // `!error` guard so a stale-data + fresh-error state still falls through
  // to the picker (or the upstream error path) instead of blanking the page.
  if (!error && me && me.allowed_roles.length === 1) return null;

  return (
    <EmptyState
      title="Pick a role to get started"
      description="Your accessible roles and buckets are listed in the sidebar."
      burgerSize={96}
    />
  );
}
