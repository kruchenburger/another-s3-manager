import { useCallback } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { listFiles } from "@/features/files/api/filesApi";

// 3-arg prefix — used by useDelete/useUpload/FileBrowser invalidateQueries.
// TanStack Query v5 matches queries whose key STARTS WITH this prefix.
export const filesQueryKey = (bucket: string, role: string, path: string) =>
  ["files", "list", role, bucket, path] as const;

/**
 * Client-load file listing. The first fetch pulls up to max_client_load objects
 * (the backend aggregates S3 pages); `loadMore` fetches the next chunk and
 * `loadAll` drains the rest. The component holds the flattened `files` in memory
 * and paginates/filters/searches client-side (vanilla parity).
 *
 * Built on useInfiniteQuery so chunks cache and survive re-renders, but the page
 * param is the opaque continuation token (a chunk-of-max_client_load), NOT
 * items_per_page — so a small folder is fully loaded in page 0 and extra chunks
 * exist only when the user explicitly asks for them.
 */
export function useFiles(
  bucket: string | undefined,
  role: string | undefined,
  path: string,
) {
  const query = useInfiniteQuery({
    queryKey:
      bucket && role
        ? filesQueryKey(bucket, role, path)
        : (["files", "list", "_disabled"] as const),
    queryFn: ({ pageParam }) => {
      const token = pageParam as string | undefined;
      return listFiles(
        bucket!,
        role!,
        path,
        token ? { continuationToken: token } : {},
      );
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_token ?? undefined,
    enabled: !!bucket && !!role,
  });

  const pages = query.data?.pages ?? [];
  const directories = pages[0]?.directories ?? [];
  const files = pages.flatMap((p) => p.files);
  const lastPage = pages[pages.length - 1];
  const truncated = lastPage ? lastPage.truncated : false;

  // fetchNextPage never rejects (throwOnError is off) — on failure it resolves
  // with an errored result and the error lands in query.error. Re-throw it so
  // the caller (FileBrowser) can toast the failure AND so the already-loaded
  // pages stay on screen instead of the whole table blanking to QueryErrorState.
  const loadMore = useCallback(async () => {
    if (!query.hasNextPage || query.isFetchingNextPage) return;
    const res = await query.fetchNextPage();
    if (res.isError) throw res.error ?? new Error("Failed to load more files");
  }, [query]);

  const loadAll = useCallback(async () => {
    if (!query.hasNextPage || query.isFetchingNextPage) return;
    let res = await query.fetchNextPage();
    if (res.isError) throw res.error ?? new Error("Failed to load files");
    while (res.hasNextPage) {
      res = await query.fetchNextPage();
      if (res.isError) throw res.error ?? new Error("Failed to load files");
    }
  }, [query]);

  return {
    ...query,
    directories,
    files,
    truncated,
    loadMore,
    loadAll,
  };
}
