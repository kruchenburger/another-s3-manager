import { useQuery } from "@tanstack/react-query";
import { fetchMe } from "@/features/auth/api/authApi";
import { setCsrfToken } from "@/utils/csrf";
import type { MeResponse } from "@/types/api";

export const meQueryKey = ["auth", "me"] as const;

export function useMe() {
  return useQuery<MeResponse>({
    queryKey: meQueryKey,
    queryFn: async () => {
      const me = await fetchMe();
      // CSRF token is rotated by /api/me on each call — sync sessionStorage so
      // mutating requests pick up the latest value.
      setCsrfToken(me.csrf_token);
      return me;
    },
    // We only care about the result for navigation gating — don't auto-poll.
    staleTime: 60_000,
  });
}
