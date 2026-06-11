import { useQuery } from "@tanstack/react-query";
import {
  getPresignedDownloadUrl,
  type PresignedUrlResponse,
} from "@/features/files/api/filesApi";

// Never cache a URL as "fresh" for less than this — guards against thrashing
// when a URL is already near its expiry.
const MIN_STALE_MS = 30_000;
// Fraction of the remaining lifetime we treat the cached URL as fresh. Leaves
// a margin so we never hand out a URL that expires mid-render.
const STALE_FRACTION = 0.8;

/**
 * Compute the staleTime (ms) for a presigned URL from its `expires_at`.
 * ~80% of the remaining lifetime, floored at 30s. Invalid/missing/expired
 * inputs return the floor.
 */
export function presignedStaleTime(expiresAt: string | undefined): number {
  if (!expiresAt) return MIN_STALE_MS;
  const expiryMs = Date.parse(expiresAt);
  if (Number.isNaN(expiryMs)) return MIN_STALE_MS;
  const remaining = expiryMs - Date.now();
  return Math.max(MIN_STALE_MS, Math.floor(remaining * STALE_FRACTION));
}

/**
 * Fetch a presigned download URL for one object. Cached per (bucket, role,
 * path). The cache lifetime follows the URL's own expiry (≈80% of remaining
 * time) instead of a fixed window, so a small configured default TTL refetches
 * sooner and a large one refetches later.
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
    // staleTime accepts a function in TanStack Query v5 — derive from the
    // fetched URL's expiry so the cache window scales with the granted TTL.
    staleTime: (query) =>
      presignedStaleTime(
        (query.state.data as PresignedUrlResponse | undefined)?.expires_at,
      ),
    // gcTime stays a generous static ceiling (must be a number, not a fn).
    gcTime: 7 * 24 * 60 * 60 * 1000,
    refetchOnWindowFocus: false,
    refetchOnMount: false,
    retry: false,
  });
}
