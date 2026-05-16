import { describe, it, expect, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useChangeMyPassword } from "@/features/auth/hooks/useChangeMyPassword";
import { ApiError } from "@/utils/apiError";

vi.mock("@/features/auth/api/authApi", () => ({
  changeMyPassword: vi.fn(),
}));

import { changeMyPassword } from "@/features/auth/api/authApi";

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

describe("useChangeMyPassword", () => {
  it("calls the API and resolves", async () => {
    vi.mocked(changeMyPassword).mockResolvedValueOnce(undefined);
    const { result } = renderHook(() => useChangeMyPassword(), { wrapper });
    result.current.mutate({ current_password: "old", new_password: "new12345" });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(changeMyPassword).toHaveBeenCalledWith({
      current_password: "old",
      new_password: "new12345",
    });
  });

  it("propagates ApiError 401 (wrong current)", async () => {
    vi.mocked(changeMyPassword).mockRejectedValueOnce(
      new ApiError(401, "Unauthorized", { detail: "Current password is incorrect" }),
    );
    const { result } = renderHook(() => useChangeMyPassword(), { wrapper });
    result.current.mutate({ current_password: "x", new_password: "y" });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as ApiError).status).toBe(401);
  });

  it("invalidates the me query on success so RequireFreshPassword sees fresh data", async () => {
    // Regression test for the infinite redirect loop: without invalidation
    // /api/me returned `must_change_password: true` from cache for up to 60s
    // (staleTime), bouncing the user back to /change-password after they had
    // just successfully changed the password.
    vi.mocked(changeMyPassword).mockResolvedValueOnce(undefined);
    const qc = new QueryClient({
      defaultOptions: { mutations: { retry: false }, queries: { retry: false } },
    });
    // Seed the me cache with a stale value.
    qc.setQueryData(["auth", "me"], {
      username: "u",
      must_change_password: true,
      allowed_roles: [],
      default_role: null,
    });
    const customWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    );
    const { result } = renderHook(() => useChangeMyPassword(), {
      wrapper: customWrapper,
    });
    result.current.mutate({ current_password: "old", new_password: "new12345" });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    // Verify the me query is now marked invalid (will refetch on next observer).
    const state = qc.getQueryState(["auth", "me"]);
    expect(state?.isInvalidated).toBe(true);
  });
});
