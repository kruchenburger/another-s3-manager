import { apiRequest } from "@/hooks/useApiClient";
import type {
  AdminUsersResponse,
  AppConfig,
  Ban,
  CreateUserPayload,
  UpdateUserPayload,
} from "@/types/api";

/**
 * Backend convention for /api/admin/users (see main.py:376-560):
 *   - GET → JSON response { users: [...], available_roles: [...] }
 *   - POST/PUT (create + update) use FastAPI Form(...) → multipart/form-data here
 *   - PUT password reset uses Body(..., embed=True) → JSON here
 *   - DELETE → no body
 *   - GET /api/admin/bans (see main.py:563) → JSON response { bans: [...] }
 *   - /api/config GET/POST → JSON in both directions
 *
 * If you add an endpoint, check main.py to confirm which convention applies.
 */

// Backend wraps the array in { bans: Ban[] } (see src/another_s3_manager/main.py
// list_bans handler). Unwrap here so callers get a flat array.
interface BansResponse {
  bans: Ban[];
}

export async function listBans(): Promise<Ban[]> {
  const data = await apiRequest<BansResponse>("/api/admin/bans");
  return data.bans;
}

export async function unbanUser(username: string): Promise<void> {
  await apiRequest<void>(
    `/api/admin/bans/${encodeURIComponent(username)}`,
    { method: "DELETE" },
  );
}

/**
 * Returns BOTH users and available_roles in one call. Backend ships them together
 * to avoid a second request for the role autocomplete in the Drawer form.
 */
export async function listUsers(): Promise<AdminUsersResponse> {
  return apiRequest<AdminUsersResponse>("/api/admin/users");
}

export async function createUser(payload: CreateUserPayload): Promise<void> {
  // Backend uses Form(...) fields — multipart, not JSON. See main.py:398-441.
  const body = new FormData();
  body.append("username", payload.username);
  body.append("password", payload.password);
  body.append("is_admin", String(payload.is_admin));
  body.append("allowed_roles", payload.allowed_roles.join(","));
  await apiRequest<void>("/api/admin/users", { method: "POST", body });
}

export async function updateUser(
  username: string,
  payload: UpdateUserPayload,
): Promise<void> {
  // Backend uses Form(...) fields. See main.py:471-496.
  const body = new FormData();
  if (payload.is_admin !== undefined) {
    body.append("is_admin", String(payload.is_admin));
  }
  if (payload.allowed_roles !== undefined) {
    body.append("allowed_roles", payload.allowed_roles.join(","));
  }
  await apiRequest<void>(
    `/api/admin/users/${encodeURIComponent(username)}`,
    { method: "PUT", body },
  );
}

export async function deleteUser(username: string): Promise<void> {
  await apiRequest<void>(
    `/api/admin/users/${encodeURIComponent(username)}`,
    { method: "DELETE" },
  );
}

export async function resetUserPassword(
  username: string,
  newPassword: string,
): Promise<void> {
  // Backend uses JSON body with field "password" via Body(..., embed=True).
  // See main.py:444-468.
  await apiRequest<void>(
    `/api/admin/users/${encodeURIComponent(username)}/password`,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: newPassword }),
    },
  );
}

export async function getConfig(): Promise<AppConfig> {
  return apiRequest<AppConfig>("/api/config");
}

export async function saveConfig(config: AppConfig): Promise<void> {
  await apiRequest<void>("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
}
