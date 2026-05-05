import { useQuery } from "@tanstack/react-query";
import {
  getPresignedDownloadUrl,
  type PresignedUrlResponse,
} from "@/features/files/api/filesApi";

// 50 minutes — under the 1h backend TTL with margin so we don't hand out an
// expired URL. Refetching more often would just burn backend CPU + S3 SigV4
// signing for no UX gain.
const PRESIGNED_STALE_MS = 50 * 60 * 1000;

/**
 * Fetch a presigned download URL for one object. Cached per (bucket, role, path).
 *
 * `enabled` lets the caller skip fetching for non-previewable files (e.g. PDF
 * in a grid card that just needs an icon). When false, no network request fires.
 */
export function usePresignedUrl(
  bucket: string,
  role: string,
  path: string,
  enabled: boolean,
) {
  return useQuery<PresignedUrlResponse>({
    queryKey: ["presigned", bucket, role, path],
    queryFn: () => getPresignedDownloadUrl(bucket, role, path),
    enabled,
    staleTime: PRESIGNED_STALE_MS,
    gcTime: PRESIGNED_STALE_MS,
    refetchOnWindowFocus: false,
    refetchOnMount: false,
    retry: false,
  });
}
