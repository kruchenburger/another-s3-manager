import type { ReactNode } from "react";
import { renderHook, waitFor, act } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi, describe, it, expect, beforeEach } from "vitest";

vi.mock("@/features/files/api/filesApi", () => ({
  listFiles: vi.fn(),
}));

import { listFiles } from "@/features/files/api/filesApi";
import { useFiles, filesQueryKey } from "@/features/files/hooks/useFiles";

const listFilesMock = listFiles as unknown as ReturnType<typeof vi.fn>;

function wrap(qc: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

function newQc() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
}

describe("useFiles (client-load)", () => {
  beforeEach(() => listFilesMock.mockReset());

  it("loads the first chunk into items + exposes truncated/next_token", async () => {
    listFilesMock.mockResolvedValueOnce({
      directories: [{ name: "logs", is_directory: true, size: 0 }],
      files: [{ name: "a.txt", is_directory: false, size: 1, last_modified: "" }],
      truncated: true,
      next_token: "tok-1",
    });

    const { result } = renderHook(() => useFiles("b", "r", "p"), {
      wrapper: wrap(newQc()),
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(listFilesMock).toHaveBeenCalledWith("b", "r", "p", {});
    expect(result.current.directories).toEqual([
      { name: "logs", is_directory: true, size: 0 },
    ]);
    expect(result.current.files).toEqual([
      { name: "a.txt", is_directory: false, size: 1, last_modified: "" },
    ]);
    expect(result.current.truncated).toBe(true);
  });

  it("loadMore appends the next chunk and clears truncated when exhausted", async () => {
    listFilesMock
      .mockResolvedValueOnce({
        directories: [],
        files: [{ name: "a.txt", is_directory: false, size: 1, last_modified: "" }],
        truncated: true,
        next_token: "tok-1",
      })
      .mockResolvedValueOnce({
        directories: [],
        files: [{ name: "b.txt", is_directory: false, size: 1, last_modified: "" }],
        truncated: false,
        next_token: null,
      });

    const { result } = renderHook(() => useFiles("b", "r", ""), {
      wrapper: wrap(newQc()),
    });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.truncated).toBe(true);

    await act(async () => {
      await result.current.loadMore();
    });

    expect(listFilesMock).toHaveBeenLastCalledWith("b", "r", "", {
      continuationToken: "tok-1",
    });
    expect(result.current.files.map((f) => f.name)).toEqual(["a.txt", "b.txt"]);
    expect(result.current.truncated).toBe(false);
  });

  it("loadAll drains every remaining chunk", async () => {
    listFilesMock
      .mockResolvedValueOnce({
        directories: [],
        files: [{ name: "a.txt", is_directory: false, size: 1, last_modified: "" }],
        truncated: true,
        next_token: "t1",
      })
      .mockResolvedValueOnce({
        directories: [],
        files: [{ name: "b.txt", is_directory: false, size: 1, last_modified: "" }],
        truncated: true,
        next_token: "t2",
      })
      .mockResolvedValueOnce({
        directories: [],
        files: [{ name: "c.txt", is_directory: false, size: 1, last_modified: "" }],
        truncated: false,
        next_token: null,
      });

    const { result } = renderHook(() => useFiles("b", "r", ""), {
      wrapper: wrap(newQc()),
    });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    await act(async () => {
      await result.current.loadAll();
    });

    expect(result.current.files.map((f) => f.name)).toEqual([
      "a.txt",
      "b.txt",
      "c.txt",
    ]);
    expect(result.current.truncated).toBe(false);
  });

  it("accumulates directories across chunks (folder pagination), deduped", async () => {
    listFilesMock
      .mockResolvedValueOnce({
        directories: [
          { name: "d1", is_directory: true, size: 0 },
          { name: "d2", is_directory: true, size: 0 },
        ],
        files: [],
        truncated: true,
        next_token: "tok-1",
      })
      .mockResolvedValueOnce({
        // A page refetch could re-surface d2; it must not duplicate.
        directories: [
          { name: "d2", is_directory: true, size: 0 },
          { name: "d3", is_directory: true, size: 0 },
        ],
        files: [],
        truncated: false,
        next_token: null,
      });

    const { result } = renderHook(() => useFiles("b", "r", ""), {
      wrapper: wrap(newQc()),
    });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.directories.map((d) => d.name)).toEqual(["d1", "d2"]);

    await act(async () => {
      await result.current.loadMore();
    });

    // Folders from both chunks are present, d2 appears once.
    expect(result.current.directories.map((d) => d.name)).toEqual(["d1", "d2", "d3"]);
    expect(result.current.truncated).toBe(false);
  });

  it("filesQueryKey is the 3-arg prefix used for invalidation", () => {
    expect(filesQueryKey("b", "r", "p")).toEqual(["files", "list", "r", "b", "p"]);
  });
});
