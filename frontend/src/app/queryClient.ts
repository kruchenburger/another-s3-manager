import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "@/utils/apiError";

// Defaults tuned for an admin tool (small audience, infrequent writes):
//   - retry: skip on auth errors, otherwise 1 retry
//   - staleTime: 30s — cuts refetch chatter on tab focus
//   - refetchOnWindowFocus: true — keeps file lists fresh after Alt-Tab
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        if (error instanceof ApiError && (error.status === 401 || error.status === 403)) return false;
        return failureCount < 1;
      },
      staleTime: 30_000,
      refetchOnWindowFocus: true,
    },
    mutations: {
      retry: false,
    },
  },
});
