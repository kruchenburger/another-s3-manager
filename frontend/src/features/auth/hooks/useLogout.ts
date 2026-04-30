import { useMutation, useQueryClient } from "@tanstack/react-query";
import { logout } from "@/features/auth/api/authApi";
import { clearCsrfToken } from "@/utils/csrf";

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: logout,
    onSuccess: () => {
      clearCsrfToken();
      // Drop ALL cached server state — the user is gone, none of it is theirs anymore.
      qc.clear();
    },
  });
}
