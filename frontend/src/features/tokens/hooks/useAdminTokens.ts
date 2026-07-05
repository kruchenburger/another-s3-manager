import { useQuery } from "@tanstack/react-query";
import { fetchAdminTokens } from "../api/tokensApi";

export function useAdminTokens() {
  return useQuery({
    queryKey: ["admin-tokens"],
    queryFn: fetchAdminTokens,
    refetchOnWindowFocus: false,
  });
}
