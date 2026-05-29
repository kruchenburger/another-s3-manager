import type { ReactNode } from "react";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi, describe, it, expect, beforeEach } from "vitest";

vi.mock("@/features/files/api/filesApi", () => ({
  listFiles: vi.fn(),
}));

import { listFiles } from "@/features/files/api/filesApi";
import {
  useFiles,
  filesQueryKey,
  filesQueryKeyFull,
} from "@/features/files/hooks/useFiles";

const listFilesMock = listFiles as unknown as ReturnType<typeof vi.fn>;

function wrap(qc: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

describe("useFiles (infinite query)", () => {
  beforeEach(() => listFilesMock.mockReset());

  it("loads the first page using pageSize as max_keys", async () => {
    listFilesMock.mockResolvedValueOnce({
      directories: [{ name: "logs", is_directory: true, size: 0 }],
      files: [
        {
          name: "a.txt",
          is_directory: false,
          size: 1,
          last_modified: "2026-01-01T00:00:00+00:00",
        },
      ],
      next_token: "tok-1",
      has_more: true,
    });
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 } },
    });

    const { result } = renderHook(
      () => useFiles("bucket-x", "role-y", "logs", 50),
      { wrapper: wrap(qc) },
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(listFilesMock).toHaveBeenCalledWith("bucket-x", "role-y", "logs", {
      maxKeys: 50,
      continuationToken: undefined,
    });
    expect(result.current.data?.pages[0].next_token).toBe("tok-1");
    expect(result.current.hasNextPage).toBe(true);
  });

  it("full queryKey includes pageSize so changing it busts the cache", () => {
    const k1 = filesQueryKeyFull("b", "r", "p", 50);
    const k2 = filesQueryKeyFull("b", "r", "p", 100);
    expect(k1).not.toEqual(k2);
    expect(k1[k1.length - 1]).toBe(50);
    expect(k2[k2.length - 1]).toBe(100);
  });

  it("3-arg filesQueryKey is a prefix of the 4-arg filesQueryKeyFull", () => {
    const prefix = filesQueryKey("b", "r", "p");
    const full = filesQueryKeyFull("b", "r", "p", 50);
    expect(full.slice(0, prefix.length)).toEqual([...prefix]);
  });

  it("fetchNextPage passes next_token from the last page", async () => {
    listFilesMock
      .mockResolvedValueOnce({
        directories: [],
        files: [
          {
            name: "a.txt",
            is_directory: false,
            size: 1,
            last_modified: "2026-01-01T00:00:00+00:00",
          },
        ],
        next_token: "tok-2",
        has_more: true,
      })
      .mockResolvedValueOnce({
        directories: [],
        files: [
          {
            name: "b.txt",
            is_directory: false,
            size: 1,
            last_modified: "2026-01-01T00:00:00+00:00",
          },
        ],
        next_token: null,
        has_more: false,
      });
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 } },
    });

    const { result } = renderHook(() => useFiles("b", "r", "", 10), {
      wrapper: wrap(qc),
    });
    await waitFor(() => expect(result.current.hasNextPage).toBe(true));

    await result.current.fetchNextPage();
    await waitFor(() => expect(listFilesMock).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(result.current.data?.pages).toHaveLength(2));

    expect(listFilesMock).toHaveBeenLastCalledWith("b", "r", "", {
      maxKeys: 10,
      continuationToken: "tok-2",
    });
    expect(result.current.hasNextPage).toBe(false);
  });
});
