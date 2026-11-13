import { describe, it, expect, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";

import { invalidateSessionOnAuthError } from "@/app/queryClient";
import { meQueryKey } from "@/features/auth/hooks/useMe";
import { ApiError } from "@/utils/apiError";

function spyClient() {
  const client = new QueryClient();
  const invalidate = vi.spyOn(client, "invalidateQueries").mockResolvedValue();
  return { client, invalidate };
}

describe("invalidateSessionOnAuthError", () => {
  it("refetches /api/me when another query gets 401, so AuthGuard can redirect to sign-in", () => {
    const { client, invalidate } = spyClient();
    invalidateSessionOnAuthError(
      client,
      new ApiError(401, "Not authenticated"),
      ["files", "role", "bucket"],
    );
    expect(invalidate).toHaveBeenCalledWith(
      { queryKey: meQueryKey },
      { cancelRefetch: false },
    );
  });

  it("ignores the /api/me query's own 401 to avoid a refetch loop", () => {
    const { client, invalidate } = spyClient();
    invalidateSessionOnAuthError(
      client,
      new ApiError(401, "Not authenticated"),
      [...meQueryKey],
    );
    expect(invalidate).not.toHaveBeenCalled();
  });

  it.each([
    ["403", new ApiError(403, "Forbidden")],
    ["500", new ApiError(500, "Server error")],
    ["non-API error", new Error("network")],
  ])("leaves the session alone on %s", (_label, error) => {
    const { client, invalidate } = spyClient();
    invalidateSessionOnAuthError(client, error, ["buckets"]);
    expect(invalidate).not.toHaveBeenCalled();
  });
});
