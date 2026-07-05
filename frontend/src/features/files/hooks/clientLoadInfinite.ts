import { useCallback } from "react";
import type { UseInfiniteQueryResult, InfiniteData } from "@tanstack/react-query";
import type { ClientLoadPage } from "@/types/api";

/**
 * Shared reducer over a client-load useInfiniteQuery: flattens pages into
 * {directories, files, truncated} and exposes loadMore/loadAll that re-throw
 * continuation errors (so the caller can toast while keeping loaded pages on
 * screen). Used by both useFiles (folder browse) and useFileSearch (server
 * prefix search) so the two stay behaviorally identical.
 */
export function useClientLoadDerived(
  query: UseInfiniteQueryResult<InfiniteData<ClientLoadPage>, Error>,
) {
  const pages = query.data?.pages ?? [];
  const directories = pages[0]?.directories ?? [];
  const files = pages.flatMap((p) => p.files);
  const lastPage = pages[pages.length - 1];
  const truncated = lastPage ? lastPage.truncated : false;

  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query;

  const loadMore = useCallback(async () => {
    if (!hasNextPage || isFetchingNextPage) return;
    const res = await fetchNextPage();
    if (res.isError) throw res.error ?? new Error("Failed to load more files");
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);

  const loadAll = useCallback(async () => {
    if (!hasNextPage || isFetchingNextPage) return;
    let res = await fetchNextPage();
    if (res.isError) throw res.error ?? new Error("Failed to load files");
    while (res.hasNextPage) {
      res = await fetchNextPage();
      if (res.isError) throw res.error ?? new Error("Failed to load files");
    }
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);

  return { directories, files, truncated, loadMore, loadAll };
}
