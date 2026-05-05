import { useQuery } from "@tanstack/react-query";
import { fetchMyTokens } from "../api/tokensApi";

export function useMyTokens() {
  return useQuery({
    queryKey: ["my-tokens"],
    queryFn: fetchMyTokens,
    refetchOnWindowFocus: false,
  });
}
