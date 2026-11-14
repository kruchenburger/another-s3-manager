import { useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchMe } from "@/features/auth/api/authApi";
import { sessionCoordinator } from "./useSessionIdentity";
import type { MeResponse } from "@/types/api";

export const meQueryKey = ["auth", "me"] as const;

export function useMe() {
  const coordinator = sessionCoordinator(useQueryClient());
  return useQuery<MeResponse>({
    queryKey: meQueryKey,
    queryFn: async () => {
      const generation = coordinator.generation;
      const me = await fetchMe();
      // CSRF token is rotated by /api/me on each call — sync sessionStorage so
      // mutating requests pick up the latest value.
      return coordinator.accept(me, generation);
    },
    // We only care about the result for navigation gating — don't auto-poll.
    staleTime: 60_000,
  });
}
