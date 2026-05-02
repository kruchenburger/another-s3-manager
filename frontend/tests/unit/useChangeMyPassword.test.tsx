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
});
