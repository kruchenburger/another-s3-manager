import { useMutation, useQueryClient } from "@tanstack/react-query";
import { deleteAdminToken, deleteMyToken } from "../api/tokensApi";

export function useDeleteMyToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => deleteMyToken(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["my-tokens"] }),
  });
}

export function useDeleteAdminToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => deleteAdminToken(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin-tokens"] }),
  });
}
