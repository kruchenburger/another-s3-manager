import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createUser,
  deleteUser,
  listUsers,
  resetUserPassword,
  updateUser,
} from "@/features/admin/api/adminApi";
import type { CreateUserPayload, UpdateUserPayload } from "@/types/api";

export const adminUsersQueryKey = ["admin", "users"] as const;

export function useAdminUsers() {
  return useQuery({ queryKey: adminUsersQueryKey, queryFn: listUsers });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateUserPayload) => createUser(payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: adminUsersQueryKey }),
  });
}

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (args: { username: string; payload: UpdateUserPayload }) =>
      updateUser(args.username, args.payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: adminUsersQueryKey }),
  });
}

export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: deleteUser,
    onSuccess: () => qc.invalidateQueries({ queryKey: adminUsersQueryKey }),
  });
}

export function useResetUserPassword() {
  return useMutation({
    mutationFn: (args: {
      username: string;
      newPassword: string;
      mustChangePassword?: boolean;
    }) => resetUserPassword(args.username, args.newPassword, args.mustChangePassword),
  });
}
