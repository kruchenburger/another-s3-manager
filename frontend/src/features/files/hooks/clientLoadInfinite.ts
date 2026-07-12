import { useCallback, useEffect, useRef, useState } from "react";
import type { UseInfiniteQueryResult, InfiniteData } from "@tanstack/react-query";
import type { ClientLoadPage } from "@/types/api";

/**
 * Shared reducer over a client-load useInfiniteQuery: flattens pages into
 * {directories, files, truncated} and exposes loadMore/loadAll that re-throw
 * continuation errors (so the caller can toast while keeping loaded pages on
 * screen). Used by both useFiles (folder browse) and useFileSearch (server
 * prefix search) so the two stay behaviorally identical.
 *
 * Directories accumulate across pages just like files: the backend paginates
 * folders and files together (both count toward max_client_load), so a level
 * with more sub-folders than one chunk reveals more of them on Load more /
 * lazy scroll. Dedupe by name defensively — a clean S3 walk never repeats a
 * CommonPrefix, but a page refetch could re-append one.
 */
export function useClientLoadDerived(
  query: UseInfiniteQueryResult<InfiniteData<ClientLoadPage>, Error>,
) {
  const pages = query.data?.pages ?? [];
  const seenDir = new Set<string>();
  const directories = pages
    .flatMap((p) => p.directories)
    .filter((d) => (seenDir.has(d.name) ? false : (seenDir.add(d.name), true)));
  const files = pages.flatMap((p) => p.files);
  const lastPage = pages[pages.length - 1];
  const truncated = lastPage ? lastPage.truncated : false;

  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query;

  // Cancellation for loadAll: a huge level (e.g. 800k sub-folders) drains in
  // thousands of ~300-object chunks, so the user must be able to stop it — and
  // it must NOT keep hammering S3 in the background after they leave the folder.
  const cancelRef = useRef(false);
  const [loadingAll, setLoadingAll] = useState(false);
  useEffect(
    // On unmount (navigating out of the folder) abort any in-flight drain.
    () => () => {
      cancelRef.current = true;
    },
    [],
  );

  const loadMore = useCallback(async () => {
    if (!hasNextPage || isFetchingNextPage) return;
    const res = await fetchNextPage();
    if (res.isError) throw res.error ?? new Error("Failed to load more files");
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);

  // Resolves true when the level ended FULLY drained (including "was already
  // fully loaded"), false when the drain stopped early (Stop button/unmount).
  // Existing callers ignore the return value; the sort gate (FileBrowser)
  // applies a pending sort only on true.
  const loadAll = useCallback(async (): Promise<boolean> => {
    if (!hasNextPage || isFetchingNextPage) return true;
    cancelRef.current = false;
    setLoadingAll(true);
    try {
      let res = await fetchNextPage();
      if (res.isError) throw res.error ?? new Error("Failed to load files");
      // Stop between chunks when the user hits Stop (or unmounts). The current
      // in-flight chunk still finishes (~1 request), then the loop halts.
      while (res.hasNextPage && !cancelRef.current) {
        res = await fetchNextPage();
        if (res.isError) throw res.error ?? new Error("Failed to load files");
      }
      // hasNextPage still true here means the loop exited on cancellation —
      // the level is NOT fully drained.
      return !res.hasNextPage;
    } finally {
      setLoadingAll(false);
    }
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);

  const stopLoadAll = useCallback(() => {
    cancelRef.current = true;
  }, []);

  return { directories, files, truncated, loadMore, loadAll, loadingAll, stopLoadAll };
}
