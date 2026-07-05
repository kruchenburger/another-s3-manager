import { useMutation, useQueryClient } from "@tanstack/react-query";

import { updateAdminToken, updateMyToken } from "../api/tokensApi";
import type {
  AdminUpdateTokenPayload,
  ApiToken,
  ApiTokenWithOwner,
  UpdateTokenPayload,
} from "@/types/api";

interface UpdateMyTokenArgs {
  id: number;
  payload: UpdateTokenPayload;
}

export function useUpdateMyToken() {
  const qc = useQueryClient();
  return useMutation<ApiToken, Error, UpdateMyTokenArgs>({
    mutationFn: ({ id, payload }) => updateMyToken(id, payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["my-tokens"] }),
  });
}

interface UpdateAdminTokenArgs {
  id: number;
  payload: AdminUpdateTokenPayload;
}

export function useUpdateAdminToken() {
  const qc = useQueryClient();
  return useMutation<ApiTokenWithOwner, Error, UpdateAdminTokenArgs>({
    mutationFn: ({ id, payload }) => updateAdminToken(id, payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin-tokens"] }),
  });
}
