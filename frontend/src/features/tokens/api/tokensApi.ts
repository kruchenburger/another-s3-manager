import { apiRequest } from "@/hooks/useApiClient";
import type {
  AdminCreateTokenPayload,
  AdminTokensResponse,
  AdminUpdateTokenPayload,
  ApiToken,
  ApiTokenWithOwner,
  ApiTokenWithPlaintext,
  CreateTokenPayload,
  MyTokensResponse,
  UpdateTokenPayload,
} from "@/types/api";

export async function fetchMyTokens(): Promise<MyTokensResponse> {
  return apiRequest<MyTokensResponse>("/api/me/tokens");
}

export async function createMyToken(
  payload: CreateTokenPayload,
): Promise<ApiTokenWithPlaintext> {
  return apiRequest<ApiTokenWithPlaintext>("/api/me/tokens", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function deleteMyToken(id: number): Promise<void> {
  return apiRequest<void>(`/api/me/tokens/${id}`, { method: "DELETE" });
}

export async function fetchAdminTokens(): Promise<AdminTokensResponse> {
  return apiRequest<AdminTokensResponse>("/api/admin/tokens");
}

export async function createAdminToken(
  payload: AdminCreateTokenPayload,
): Promise<ApiTokenWithPlaintext> {
  return apiRequest<ApiTokenWithPlaintext>("/api/admin/tokens", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function deleteAdminToken(id: number): Promise<void> {
  return apiRequest<void>(`/api/admin/tokens/${id}`, { method: "DELETE" });
}

export async function updateMyToken(
  id: number,
  payload: UpdateTokenPayload,
): Promise<ApiToken> {
  return apiRequest<ApiToken>(`/api/me/tokens/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function updateAdminToken(
  id: number,
  payload: AdminUpdateTokenPayload,
): Promise<ApiTokenWithOwner> {
  return apiRequest<ApiTokenWithOwner>(`/api/admin/tokens/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
