import { useMutation, useQueryClient } from "@tanstack/react-query";
import { login } from "@/features/auth/api/authApi";
import { meQueryKey } from "@/features/auth/hooks/useMe";
import type { LoginResponse } from "@/types/api";

export function useLogin() {
  const qc = useQueryClient();
  return useMutation<LoginResponse, Error, { username: string; password: string }>({
    mutationFn: ({ username, password }) => login(username, password),
    onSuccess: () => {
      // Force /api/me refetch so CSRF + user info land in cache + sessionStorage.
      qc.invalidateQueries({ queryKey: meQueryKey });
    },
  });
}
