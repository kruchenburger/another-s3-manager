import { apiRequest } from "@/hooks/useApiClient";
import { ApiError } from "@/utils/apiError";
import type {
  AdminUsersResponse,
  AppConfig,
  Ban,
  CreateUserPayload,
  UpdateUserPayload,
} from "@/types/api";

/**
 * Backend conventions for the admin endpoints consumed here. Cross-reference
 * by FastAPI decorator (line numbers rot — endpoint paths don't):
 *   - GET  @app.get("/api/admin/users")    → JSON { users: [...], available_roles: [...] }
 *   - POST @app.post("/api/admin/users")   → FastAPI Form(...) (multipart) here
 *   - PUT  @app.put("/api/admin/users/{username}") → Form(...) (multipart) here
 *   - PUT  @app.put("/api/admin/users/{username}/password") → Body(..., embed=True) (JSON)
 *   - DELETE @app.delete("/api/admin/users/{username}") → no body
 *   - GET  @app.get("/api/admin/bans")     → JSON { bans: [...] }
 *   - DELETE @app.delete("/api/admin/bans/{username}") → no body
 *   - GET/POST @app.get/@app.post("/api/config") → JSON in both directions
 *
 * If you add an endpoint, grep main.py for the decorator string to confirm
 * which body convention applies.
 */

// Backend wraps the array in { bans: Ban[] } (see src/another_s3_manager/main.py
// `@app.get("/api/admin/bans")` handler). Unwrap here so callers get a flat array.
interface BansResponse {
  bans: Ban[];
}

export async function listBans(): Promise<Ban[]> {
  const data = await apiRequest<BansResponse>("/api/admin/bans");
  return data.bans;
}

export async function unbanUser(username: string): Promise<void> {
  await apiRequest<void>(`/api/admin/bans/${encodeURIComponent(username)}`, {
    method: "DELETE",
  });
}

/**
 * Returns BOTH users and available_roles in one call. Backend ships them together
 * to avoid a second request for the role autocomplete in the Drawer form.
 */
export async function listUsers(): Promise<AdminUsersResponse> {
  return apiRequest<AdminUsersResponse>("/api/admin/users");
}

export async function createUser(payload: CreateUserPayload): Promise<void> {
  // Backend uses FastAPI Form(...) fields (multipart, not JSON). See main.py
  // `@app.post("/api/admin/users")` create_user handler.
  const body = new FormData();
  body.append("username", payload.username);
  body.append("password", payload.password);
  body.append("is_admin", String(payload.is_admin));
  body.append("allowed_roles", payload.allowed_roles.join(","));
  if (payload.must_change_password !== undefined) {
    body.append("must_change_password", String(payload.must_change_password));
  }
  await apiRequest<void>("/api/admin/users", { method: "POST", body });
}

export async function updateUser(
  username: string,
  payload: UpdateUserPayload,
): Promise<void> {
  // Backend uses FastAPI Form(...) fields (multipart). See main.py
  // `@app.put("/api/admin/users/{username}")` update_user handler.
  const body = new FormData();
  if (payload.is_admin !== undefined) {
    body.append("is_admin", String(payload.is_admin));
  }
  if (payload.allowed_roles !== undefined) {
    body.append("allowed_roles", payload.allowed_roles.join(","));
  }
  await apiRequest<void>(`/api/admin/users/${encodeURIComponent(username)}`, {
    method: "PUT",
    body,
  });
}

export async function deleteUser(username: string): Promise<void> {
  await apiRequest<void>(`/api/admin/users/${encodeURIComponent(username)}`, {
    method: "DELETE",
  });
}

export async function resetUserPassword(
  username: string,
  newPassword: string,
  mustChangePassword?: boolean,
): Promise<void> {
  // Backend uses JSON body with field "password" via Body(..., embed=True).
  // See main.py `@app.put("/api/admin/users/{username}/password")` handler.
  await apiRequest<void>(
    `/api/admin/users/${encodeURIComponent(username)}/password`,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        password: newPassword,
        ...(mustChangePassword !== undefined && {
          must_change_password: mustChangePassword,
        }),
      }),
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

/**
 * Fetch the raw config export as a Blob for browser download.
 *
 * apiRequest() unconditionally parses JSON; for "save the response to disk"
 * we need the raw bytes so the saved file is the exact server JSON, not a
 * re-stringified version. Hence the direct fetch here.
 *
 * Backed by GET /api/config/export (admin-gated in main.py).
 */
export async function exportConfig(): Promise<Blob> {
  const response = await fetch("/api/config/export", {
    method: "GET",
    credentials: "include",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new ApiError(
      response.status,
      response.statusText || `HTTP ${response.status}`,
      null,
    );
  }
  return response.blob();
}
