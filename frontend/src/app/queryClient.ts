import { QueryCache, QueryClient, type QueryKey } from "@tanstack/react-query";
import { meQueryKey } from "@/features/auth/hooks/useMe";
import { ApiError } from "@/utils/apiError";

function isMeQuery(queryKey: QueryKey): boolean {
  return (
    queryKey.length === meQueryKey.length &&
    meQueryKey.every((part, i) => queryKey[i] === part)
  );
}

// An expired or revoked session first surfaces on whatever query runs next (file list,
// buckets, tokens). Refetching /api/me lets AuthGuard send the user to sign-in instead of
// leaving a "Not authenticated" error on every panel. The /api/me query itself is
// excluded: its own 401 is AuthGuard's signal, and invalidating it again would loop.
export function invalidateSessionOnAuthError(
  client: QueryClient,
  error: unknown,
  queryKey: QueryKey,
): void {
  if (
    error instanceof ApiError &&
    error.isAuthError() &&
    !isMeQuery(queryKey)
  ) {
    // cancelRefetch: false — several panels failing together share one /api/me request.
    void client.invalidateQueries(
      { queryKey: meQueryKey },
      { cancelRefetch: false },
    );
  }
}

// Defaults tuned for an admin tool (small audience, infrequent writes):
//   - retry: skip on auth errors, otherwise 1 retry
//   - staleTime: 30s — cuts refetch chatter on tab focus
//   - refetchOnWindowFocus: true — keeps file lists fresh after Alt-Tab
export const queryClient: QueryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (error, query) =>
      invalidateSessionOnAuthError(queryClient, error, query.queryKey),
  }),
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        if (
          error instanceof ApiError &&
          (error.status === 401 || error.status === 403)
        )
          return false;
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
