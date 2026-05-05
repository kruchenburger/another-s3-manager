import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { AdminCreateTokenPayload, CreateTokenPayload } from "@/types/api";
import { createAdminToken, createMyToken } from "../api/tokensApi";

export function useCreateMyToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateTokenPayload) => createMyToken(payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["my-tokens"] }),
  });
}

export function useCreateAdminToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: AdminCreateTokenPayload) => createAdminToken(payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin-tokens"] }),
  });
}
