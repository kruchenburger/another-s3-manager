import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getConfig, saveConfig } from "@/features/admin/api/adminApi";
import type { AppConfig } from "@/types/api";

export const adminConfigQueryKey = ["admin", "config"] as const;

export function useAdminConfig() {
  return useQuery({ queryKey: adminConfigQueryKey, queryFn: getConfig });
}

export function useSaveConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (config: AppConfig) => saveConfig(config),
    onSuccess: () => qc.invalidateQueries({ queryKey: adminConfigQueryKey }),
  });
}
