import { useInfiniteQuery } from "@tanstack/react-query";
import { listFiles } from "@/features/files/api/filesApi";
import { useClientLoadDerived } from "@/features/files/hooks/clientLoadInfinite";

// Separate cache namespace from the folder listing ("list") so entering/exiting
// server search never evicts the folder's loaded pages. NOTE: the delete/upload
// mutations invalidate only the ["files","list",...] folder key, so a component
// showing server-search results must also invalidate this ["files","search",...]
// key after a mutation (handled where FileBrowser wires useFileSearch).
export const fileSearchQueryKey = (
  bucket: string,
  role: string,
  path: string,
  term: string,
) => ["files", "search", role, bucket, path, term] as const;

/**
 * Server-side prefix search. Runs only when `term` is non-empty. Same chunked
 * shape as useFiles (loadMore/loadAll/truncated) so FileBrowser can swap it in
 * as the active source with no downstream changes.
 */
export function useFileSearch(
  bucket: string | undefined,
  role: string | undefined,
  path: string,
  term: string,
) {
  const enabled = !!bucket && !!role && term.length > 0;
  const query = useInfiniteQuery({
    queryKey: enabled
      ? fileSearchQueryKey(bucket!, role!, path, term)
      : (["files", "search", "_disabled"] as const),
    queryFn: ({ pageParam }) => {
      const token = pageParam as string | undefined;
      return listFiles(bucket!, role!, path, {
        search: term,
        ...(token ? { continuationToken: token } : {}),
      });
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_token ?? undefined,
    enabled,
  });

  const derived = useClientLoadDerived(query);
  return { ...query, ...derived };
}
