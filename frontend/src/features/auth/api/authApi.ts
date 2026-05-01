import { apiRequest } from "@/hooks/useApiClient";
import type { LoginResponse, MeResponse } from "@/types/api";

export async function login(username: string, password: string): Promise<LoginResponse> {
  const body = new FormData();
  body.append("username", username);
  body.append("password", password);
  // /api/login is form-encoded (FastAPI Form fields), NOT JSON.
  return apiRequest<LoginResponse>("/api/login", { method: "POST", body });
}

export async function logout(): Promise<void> {
  await apiRequest<void>("/api/logout", { method: "POST" });
}

export async function fetchMe(): Promise<MeResponse> {
  return apiRequest<MeResponse>("/api/me");
}

export async function markTourSeen(): Promise<void> {
  await apiRequest<void>("/api/user/tour-seen", { method: "PUT" });
}
