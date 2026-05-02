import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getConfig, saveConfig } from "@/features/admin/api/adminApi";
import type { AppConfig } from "@/types/api";

export const adminConfigQueryKey = ["admin", "config"] as const;

export function useAdminConfig() {
  return useQuery({
    queryKey: adminConfigQueryKey,
    queryFn: getConfig,
    // Admin config drives controlled forms; refetching on window focus would
    // reset useEffect-populated form state (Settings/RoleEdit) and silently
    // wipe in-progress edits or flip isDirty back to false (dropping the
    // byte-precision preservation in SettingsPage MB→bytes save). Refetch
    // explicitly via invalidateQueries on save — that's the only time we
    // want fresh data while a form is open.
    refetchOnWindowFocus: false,
  });
}

export function useSaveConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (config: AppConfig) => saveConfig(config),
    onSuccess: () => qc.invalidateQueries({ queryKey: adminConfigQueryKey }),
  });
}
