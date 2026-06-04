import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getConfig, saveConfig } from "@/features/admin/api/adminApi";
import { meQueryKey } from "@/features/auth/hooks/useMe";
import { configQueryKey } from "@/hooks/useConfig";
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
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: adminConfigQueryKey });
      // /api/me surfaces config-derived flags (currently disable_deletion;
      // future flags too). Invalidate so the FileBrowser disable-Delete UX
      // and any other useMe consumers reflect the new config without a
      // page reload. Without this, the browser keeps stale me data for up
      // to 60s (useMe.staleTime).
      qc.invalidateQueries({ queryKey: meQueryKey });
      // Public /api/config (useConfig) drives FileBrowser pagination + preview
      // behaviour (items_per_page, enable_lazy_loading, max_client_load,
      // auto_inline_extensions). Without this, those changes stay stale in an
      // open file-browser tab until useConfig's staleTime expires.
      qc.invalidateQueries({ queryKey: configQueryKey });
    },
  });
}
