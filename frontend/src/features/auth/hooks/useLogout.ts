import { useMutation, useQueryClient } from "@tanstack/react-query";
import { logout } from "@/features/auth/api/authApi";
import { sessionCoordinator } from "./useSessionIdentity";

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    meta: { authentication: true },
    mutationFn: logout,
    onSuccess: () => {
      // Drop ALL cached server state — the user is gone, none of it is theirs anymore.
      sessionCoordinator(qc).logout();
    },
  });
}
