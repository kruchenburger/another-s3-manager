import { apiRequest } from "@/hooks/useApiClient";
import type { Ban } from "@/types/api";

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
