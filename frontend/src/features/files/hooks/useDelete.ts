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
}

export function useDelete() {
  const qc = useQueryClient();
  return useMutation<void, Error, DeleteVariables>({
    mutationFn: ({ bucket, role, path }) => deleteFile(bucket, role, path),
    onSuccess: (_, { bucket, role, currentPath }) => {
      qc.invalidateQueries({ queryKey: filesQueryKey(bucket, role, currentPath) });
    },
  });
}
