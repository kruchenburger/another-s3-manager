import { useQuery } from "@tanstack/react-query";
import { listBuckets } from "@/features/files/api/filesApi";

export const bucketsQueryKey = (role: string) => ["files", "buckets", role] as const;

export function useBuckets(role: string | undefined) {
  return useQuery({
    queryKey: role ? bucketsQueryKey(role) : ["files", "buckets", "_disabled"],
    queryFn: () => listBuckets(role!),
    enabled: !!role,
  });
}
