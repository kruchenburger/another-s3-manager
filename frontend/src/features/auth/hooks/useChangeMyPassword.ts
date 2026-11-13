import { useMutation, useQueryClient } from "@tanstack/react-query";
import { changeMyPassword } from "@/features/auth/api/authApi";
import { clearCsrfToken } from "@/utils/csrf";
import type { ChangeMyPasswordPayload } from "@/types/api";

export function useChangeMyPassword() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: ChangeMyPasswordPayload) => changeMyPassword(payload),
    onSuccess: async () => {
      // The password write invalidates this session; never refetch protected me.
      await qc.cancelQueries();
      clearCsrfToken();
      qc.clear();
    },
  });
}
