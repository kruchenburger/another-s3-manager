import { useQuery } from "@tanstack/react-query";
import {
  getPresignedDownloadUrl,
  type PresignedUrlResponse,
} from "@/features/files/api/filesApi";

// Fraction of the remaining lifetime we treat the cached URL as fresh. Leaves
// a 20% margin so we never hand out a URL that expires mid-render.
const STALE_FRACTION = 0.8;

/**
 * Compute the staleTime (ms) for a presigned URL from its `expires_at`.
 * ~80% of the remaining lifetime. An already-expired (or missing/invalid)
 * URL returns 0 so the cached entry is immediately stale and gets refetched
 * on the next mount instead of being served broken. There is deliberately NO
 * lower floor: a floor would mark a near-/just-expired URL as "fresh" and let
 * a remount serve it from cache past its expiry.
 */
export function presignedStaleTime(expiresAt: string | undefined): number {
  if (!expiresAt) return 0;
  const expiryMs = Date.parse(expiresAt);
  if (Number.isNaN(expiryMs)) return 0;
  const remaining = expiryMs - Date.now();
  if (remaining <= 0) return 0;
  return Math.floor(remaining * STALE_FRACTION);
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
    // gcTime is a generous static ceiling so a long-lived URL stays cached for
    // its whole life (must be a number, not a fn). It does NOT cause expired
    // URLs to be served: an expired entry has staleTime 0, so the default
    // refetchOnMount refetches it on remount. A still-fresh entry is not stale,
    // so remounting it does not trigger a refetch (no wasted SigV4 signing).
    gcTime: 7 * 24 * 60 * 60 * 1000,
    refetchOnWindowFocus: false,
    retry: false,
  });
}
