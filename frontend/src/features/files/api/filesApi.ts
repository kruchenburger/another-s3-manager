import { apiRequest } from "@/hooks/useApiClient";
import type { BucketList, FileListResponse } from "@/types/api";

export async function listBuckets(role: string): Promise<BucketList> {
  const params = new URLSearchParams({ role });
  return apiRequest<BucketList>(`/api/buckets?${params}`);
}

export async function listFiles(bucket: string, role: string, path: string): Promise<FileListResponse> {
  const params = new URLSearchParams({ role });
  if (path) params.set("path", path);
  return apiRequest<FileListResponse>(`/api/buckets/${encodeURIComponent(bucket)}/files?${params}`);
}

export async function uploadFile(
  bucket: string,
  role: string,
  key: string,
  file: File,
): Promise<void> {
  const body = new FormData();
  body.append("file", file);
  body.append("key", key);
  body.append("role", role);
  await apiRequest<void>(`/api/buckets/${encodeURIComponent(bucket)}/upload`, {
    method: "POST",
    body,
  });
}

export async function deleteFile(bucket: string, role: string, path: string): Promise<void> {
  // path can be a folder (ends with /) — backend handles recursive delete
  const params = new URLSearchParams({ role, path });
  await apiRequest<void>(`/api/buckets/${encodeURIComponent(bucket)}/files?${params}`, {
    method: "DELETE",
  });
}

export function buildDownloadUrl(bucket: string, role: string, path: string): string {
  // Browser-triggered download via <a href> — relies on cookie auth (same-origin GET).
  const params = new URLSearchParams({ role, path });
  return `/api/buckets/${encodeURIComponent(bucket)}/download?${params}`;
}
