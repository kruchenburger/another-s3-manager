import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/hooks/useApiClient";
import type { AppConfig } from "@/types/api";

export const configQueryKey = ["config"] as const;

// Wraps GET /api/config. Used by /v2 to read `items_per_page` and
// `enable_lazy_loading` so the file browser honours the admin pagination
// settings end-to-end. Cached for 5 min — these values only change when an
// admin edits the config file. Mirrors the shape of useAppInfo.
export function useConfig() {
  return useQuery<AppConfig>({
    queryKey: configQueryKey,
    queryFn: () => apiRequest<AppConfig>("/api/config"),
    staleTime: 5 * 60_000,
  });
}
