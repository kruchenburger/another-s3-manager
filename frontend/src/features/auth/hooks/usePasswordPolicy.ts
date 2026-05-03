import { useQuery } from "@tanstack/react-query";
import { getConfig } from "@/features/admin/api/adminApi";
import { adminConfigQueryKey } from "@/features/admin/hooks/useAdminConfig";
import type { PasswordPolicy } from "@/types/api";

/**
 * Read the password policy from the cached /api/config response.
 *
 * Uses the same query key as useAdminConfig so the cache is shared — a
 * non-admin viewing /v2/change-password reuses the existing query if an
 * admin already loaded /v2/admin/settings, and vice versa. The endpoint
 * is gated on get_current_user (not get_current_admin_user), so any
 * authenticated user can fetch it.
 */
export function usePasswordPolicy() {
  return useQuery({
    queryKey: adminConfigQueryKey,
    queryFn: getConfig,
    refetchOnWindowFocus: false,
    select: (config): PasswordPolicy => ({
      password_min_length: config.password_min_length,
      password_min_uppercase: config.password_min_uppercase,
      password_min_lowercase: config.password_min_lowercase,
      password_min_digits: config.password_min_digits,
      password_min_special: config.password_min_special,
    }),
  });
}
