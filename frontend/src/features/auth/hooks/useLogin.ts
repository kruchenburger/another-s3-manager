import { useMutation, useQueryClient } from "@tanstack/react-query";
import { login } from "@/features/auth/api/authApi";
import { sessionCoordinator } from "./useSessionIdentity";
import type { LoginResponse } from "@/types/api";

export function useLogin() {
  const qc = useQueryClient();
  return useMutation<
    LoginResponse,
    Error,
    { username: string; password: string }
  >({
    meta: { authentication: true },
    mutationFn: ({ username, password }) => login(username, password),
    onSuccess: () =>
      // Reset (not just invalidate) /api/me and wait for it before the caller navigates:
      // after an expired session the cached query still holds the old data with its 401,
      // and AuthGuard would read that as "session ended" and bounce back to /login.
      // The refetch also lands CSRF + user info in cache + sessionStorage.
      sessionCoordinator(qc).refresh(true),
  });
}
