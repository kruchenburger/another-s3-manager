import { useMutation, useQueryClient } from "@tanstack/react-query";
import { changeMyPassword } from "@/features/auth/api/authApi";
import { meQueryKey } from "@/features/auth/hooks/useMe";
import type { ChangeMyPasswordPayload } from "@/types/api";

// Invalidate /api/me on success AND await the refetch before resolving the
// mutation. The backend clears `must_change_password` after a successful
// change, and `RequireFreshPassword` reads that flag from the TanStack cache.
//
// Without awaiting the refetch, callers that navigate on success (e.g.
// ChangePasswordPage → navigate("/")) would race the guard: navigate fires
// synchronously, then the guard reads the still-stale `must_change_password: true`
// and bounces the user back to /change-password. By awaiting the refetch in
// onSuccess, the mutation only resolves after `me` is fresh — so the caller's
// downstream onSuccess (navigate) sees the updated flag.
export function useChangeMyPassword() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: ChangeMyPasswordPayload) => changeMyPassword(payload),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: meQueryKey });
    },
  });
}
