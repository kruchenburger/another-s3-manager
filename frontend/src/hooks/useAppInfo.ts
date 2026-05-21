import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/hooks/useApiClient";
import type { AppInfo } from "@/types/api";

export const appInfoQueryKey = ["app-info"] as const;

// Wraps GET /api/app-info (public, no auth) so pre-login surfaces like
// LoginPage can show the current app name/version without first hitting
// /api/me. Cached for 5 min since these values only change on deploy.
export function useAppInfo() {
  return useQuery<AppInfo>({
    queryKey: appInfoQueryKey,
    queryFn: () => apiRequest<AppInfo>("/api/app-info"),
    staleTime: 5 * 60_000,
  });
}
