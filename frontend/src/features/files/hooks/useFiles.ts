import { useQuery } from "@tanstack/react-query";
import { listFiles } from "@/features/files/api/filesApi";

export const filesQueryKey = (bucket: string, role: string, path: string) =>
  ["files", "list", role, bucket, path] as const;

export function useFiles(bucket: string | undefined, role: string | undefined, path: string) {
  return useQuery({
    queryKey: bucket && role ? filesQueryKey(bucket, role, path) : ["files", "list", "_disabled"],
    queryFn: () => listFiles(bucket!, role!, path),
    enabled: !!bucket && !!role,
  });
}
