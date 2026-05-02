import { useMutation } from "@tanstack/react-query";
import { changeMyPassword } from "@/features/auth/api/authApi";
import type { ChangeMyPasswordPayload } from "@/types/api";

// No invalidateQueries: there is no cached server state about the password
// (/api/me does not return any password material).
export function useChangeMyPassword() {
  return useMutation({
    mutationFn: (payload: ChangeMyPasswordPayload) => changeMyPassword(payload),
  });
}
