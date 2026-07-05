import { useMutation, useQueryClient } from "@tanstack/react-query";
import { updateMyDefaultRole } from "@/features/auth/api/defaultRoleApi";
import { meQueryKey } from "@/features/auth/hooks/useMe";

export function useUpdateMyDefaultRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (role: string | null) => updateMyDefaultRole(role),
    onSuccess: () => {
      // /api/me now returns the new computed default_role — refresh the cache
      // so the picker shows the chosen value immediately.
      qc.invalidateQueries({ queryKey: meQueryKey });
    },
  });
}
