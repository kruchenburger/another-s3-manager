import { useMutation, useQueryClient } from "@tanstack/react-query";
import { deleteFile } from "@/features/files/api/filesApi";
import { filesQueryKey } from "@/features/files/hooks/useFiles";

interface DeleteVariables {
  bucket: string;
  role: string;
  /** Single file/folder path. For bulk, call mutate multiple times in parallel. */
  path: string;
  /** Path the user is currently viewing — invalidate just this query on success */
  currentPath: string;
  /**
   * Skip query invalidation on success. Bulk-delete callers set this to true
   * and run ONE invalidation at the end of the batch — otherwise deleting N
   * files from the currently-open folder triggers N listFiles refetches and
   * each one renders before the next delete fires, slowing the batch ~5x
   * vs deleting from a folder that isn't on screen.
   */
  skipInvalidation?: boolean;
}

export function useDelete() {
  const qc = useQueryClient();
  return useMutation<void, Error, DeleteVariables>({
    mutationFn: ({ bucket, role, path }) => deleteFile(bucket, role, path),
    onSuccess: (_, { bucket, role, currentPath, skipInvalidation }) => {
      if (skipInvalidation) return;
      qc.invalidateQueries({
        queryKey: filesQueryKey(bucket, role, currentPath),
      });
    },
  });
}
