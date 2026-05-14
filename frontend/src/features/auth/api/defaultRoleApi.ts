import { apiRequest } from "@/hooks/useApiClient";

export async function updateMyDefaultRole(role: string | null): Promise<void> {
  await apiRequest<void>("/api/me/default-role", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role }),
  });
}
