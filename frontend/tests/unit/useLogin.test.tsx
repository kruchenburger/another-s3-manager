import { describe, it, expect, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { useLogin } from "@/features/auth/hooks/useLogin";
import { meQueryKey } from "@/features/auth/hooks/useMe";

vi.mock("@/features/auth/api/authApi", () => ({
  login: vi.fn().mockResolvedValue({}),
}));

describe("useLogin", () => {
  it("resets /api/me and waits for it before the caller's onSuccess runs", async () => {
    const qc = new QueryClient();
    let resolveReset: () => void = () => {};
    const reset = vi
      .spyOn(qc, "resetQueries")
      .mockImplementation(() => new Promise<void>((r) => (resolveReset = r)));
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    );
    const { result } = renderHook(() => useLogin(), { wrapper });

    const navigated = vi.fn();
    result.current.mutate(
      { username: "alice", password: "pw" },
      { onSuccess: navigated },
    );

    await waitFor(() =>
      expect(reset).toHaveBeenCalledWith({ queryKey: meQueryKey }),
    );
    expect(navigated).not.toHaveBeenCalled();
    resolveReset();
    await waitFor(() => expect(navigated).toHaveBeenCalledTimes(1));
  });
});
