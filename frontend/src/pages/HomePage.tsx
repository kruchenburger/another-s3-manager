import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { EmptyState } from "@/components/EmptyState/EmptyState";
import { useMe } from "@/features/auth/hooks/useMe";

export function HomePage() {
  const { data: me, error } = useMe();
  const navigate = useNavigate();

  // Auto-redirect to the user's default role on landing:
  // - explicit default_role (set via DefaultRolePicker) wins
  // - else first of allowed_roles (single-role users land directly there)
  // - else (no roles) show the empty picker
  //
  // The `!error` guard mirrors RolePage (commit cf47557): TanStack Query can
  // hand back stale `me` while a fresh /api/me errors. Without this guard the
  // effect would silently navigate past the error path that AuthGuard /
  // ErrorBoundary should show.
  const target =
    me && me.allowed_roles.length > 0
      ? me.default_role && me.allowed_roles.includes(me.default_role)
        ? me.default_role
        : me.allowed_roles[0]
      : null;

  useEffect(() => {
    if (!error && target) {
      navigate(`/r/${encodeURIComponent(target)}`, { replace: true });
    }
  }, [target, navigate, error]);

  // Render nothing while the redirect fires (don't flash the picker).
  if (!error && target) return null;

  return (
    <EmptyState
      title="Pick a role to get started"
      description="Your accessible roles and buckets are listed in the sidebar."
      burgerSize={96}
    />
  );
}
