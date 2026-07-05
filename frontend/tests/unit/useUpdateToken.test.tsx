import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import {
  useUpdateMyToken,
  useUpdateAdminToken,
} from "@/features/tokens/hooks/useUpdateToken";
import * as tokensApi from "@/features/tokens/api/tokensApi";

function makeWrapper() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
  return { client, wrapper };
}

describe("useUpdateMyToken", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("calls updateMyToken and invalidates ['my-tokens'] on success", async () => {
    const apiSpy = vi
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .spyOn(tokensApi, "updateMyToken")
      .mockResolvedValue({
        id: 1,
        name: "renamed",
        is_read_only: false,
        max_read_bytes: 1024,
        created_at: "2026-05-05T00:00:00Z",
        last_used_at: null,
        revoked_at: null,
      });
    const { client, wrapper } = makeWrapper();
    const invalidateSpy = vi.spyOn(client, "invalidateQueries");

    const { result } = renderHook(() => useUpdateMyToken(), { wrapper });
    await result.current.mutateAsync({ id: 1, payload: { name: "renamed" } });

    expect(apiSpy).toHaveBeenCalledWith(1, { name: "renamed" });
    await waitFor(() =>
      expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["my-tokens"] }),
    );
  });
});

describe("useUpdateAdminToken", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("calls updateAdminToken and invalidates ['admin-tokens'] on success", async () => {
    const apiSpy = vi
      .spyOn(tokensApi, "updateAdminToken")
      .mockResolvedValue({
        id: 7,
        name: "renamed",
        is_read_only: true,
        max_read_bytes: 4096,
        created_at: "2026-05-05T00:00:00Z",
        last_used_at: null,
        revoked_at: null,
        owner_username: "alice",
      });
    const { client, wrapper } = makeWrapper();
    const invalidateSpy = vi.spyOn(client, "invalidateQueries");

    const { result } = renderHook(() => useUpdateAdminToken(), { wrapper });
    await result.current.mutateAsync({ id: 7, payload: { max_read_bytes: 4096 } });

    expect(apiSpy).toHaveBeenCalledWith(7, { max_read_bytes: 4096 });
    await waitFor(() =>
      expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["admin-tokens"] }),
    );
  });
});
