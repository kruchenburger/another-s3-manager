import { useMutation, useQueryClient } from "@tanstack/react-query";
import { markTourSeen } from "@/features/auth/api/authApi";
import { meQueryKey } from "@/features/auth/hooks/useMe";

export function useTourSeen() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: markTourSeen,
    onSuccess: () => {
      // Invalidate the /api/me cache so consumers see updated tour_seen flag.
      qc.invalidateQueries({ queryKey: meQueryKey });
    },
  });
}
