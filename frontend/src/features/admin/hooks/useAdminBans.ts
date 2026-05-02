import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listBans, unbanUser } from "@/features/admin/api/adminApi";

export const adminBansQueryKey = ["admin", "bans"] as const;

export function useAdminBans() {
  return useQuery({
    queryKey: adminBansQueryKey,
    queryFn: listBans,
  });
}

export function useUnbanUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: unbanUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: adminBansQueryKey });
    },
  });
}
