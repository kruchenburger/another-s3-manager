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
}

export function useUpload() {
  const qc = useQueryClient();
  return useMutation<void, Error, UploadVariables>({
    mutationFn: ({ bucket, role, key, file }) => uploadFile(bucket, role, key, file),
    onSuccess: (_, { bucket, role, currentPath }) => {
      qc.invalidateQueries({ queryKey: filesQueryKey(bucket, role, currentPath) });
    },
  });
}
