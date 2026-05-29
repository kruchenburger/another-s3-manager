import { useInfiniteQuery } from "@tanstack/react-query";
import { listFiles } from "@/features/files/api/filesApi";

// Prefix shape (3 args) — used by everywhere that invalidates the files cache
// (useDelete, useUpload, FileBrowser bulk handlers). TanStack Query v5 matches
// queries whose key STARTS WITH this prefix, so a single invalidation covers
// every pageSize variant stored under the same path.
export const filesQueryKey = (bucket: string, role: string, path: string) =>
  ["files", "list", role, bucket, path] as const;

// Full shape (4 args) — used inside useFiles itself. Including pageSize in
// the key means changing the admin `items_per_page` setting busts the cache
// cleanly: pages of the old size aren't reused for queries of the new size.
export const filesQueryKeyFull = (
  bucket: string,
  role: string,
  path: string,
  pageSize: number,
) => ["files", "list", role, bucket, path, pageSize] as const;

export function useFiles(
  bucket: string | undefined,
  role: string | undefined,
  path: string,
  pageSize: number,
) {
  return useInfiniteQuery({
    queryKey:
      bucket && role
        ? filesQueryKeyFull(bucket, role, path, pageSize)
        : (["files", "list", "_disabled"] as const),
    queryFn: ({ pageParam }) =>
      listFiles(bucket!, role!, path, {
        maxKeys: pageSize,
        continuationToken: pageParam as string | undefined,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_token ?? undefined,
    enabled: !!bucket && !!role,
  });
}
