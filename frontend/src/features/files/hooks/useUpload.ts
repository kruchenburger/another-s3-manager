import { useMutation, useQueryClient } from "@tanstack/react-query";
import { uploadFile } from "@/features/files/api/filesApi";
import { filesQueryKey } from "@/features/files/hooks/useFiles";

interface UploadVariables {
  bucket: string;
  role: string;
  key: string;
  file: File;
  /** Path the user is currently viewing — invalidate just this query on success */
  currentPath: string;
  /** Called periodically with 0..100 percent of the current file's body uploaded. */
  onProgress?: (percent: number) => void;
  /** AbortSignal — when triggered, the in-flight upload is cancelled. */
  signal?: AbortSignal;
  /**
   * Skip query invalidation on success. Bulk-upload callers set this to true
   * and run ONE invalidation at the end of the batch — otherwise uploading N
   * files into the currently-open folder triggers N listFiles refetches and
   * the file table flickers (loader → table → loader → table…) while files
   * stream in. Mirrors the same pattern used by useDelete for bulk-delete.
   */
  skipInvalidation?: boolean;
}

export function useUpload() {
  const qc = useQueryClient();
  return useMutation<void, Error, UploadVariables>({
    mutationFn: ({ bucket, role, key, file, onProgress, signal }) =>
      uploadFile(bucket, role, key, file, { onProgress, signal }),
    onSuccess: (_, { bucket, role, currentPath, skipInvalidation }) => {
      if (skipInvalidation) return;
      qc.invalidateQueries({ queryKey: filesQueryKey(bucket, role, currentPath) });
    },
  });
}
