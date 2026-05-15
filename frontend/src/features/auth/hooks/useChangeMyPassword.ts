import { useMutation, useQueryClient } from "@tanstack/react-query";
import { changeMyPassword } from "@/features/auth/api/authApi";
import { meQueryKey } from "@/features/auth/hooks/useMe";
import type { ChangeMyPasswordPayload } from "@/types/api";

// Invalidate /api/me on success: the backend clears `must_change_password`
// after a successful change, and `RequireFreshPassword` reads that flag from
// the TanStack cache. Without invalidation `useMe.staleTime=60_000` would
// keep the cached `must_change_password: true` for up to a minute, looping
// the user back to /change-password after they just changed it.
export function useChangeMyPassword() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: ChangeMyPasswordPayload) => changeMyPassword(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: meQueryKey });
    },
  });
}
