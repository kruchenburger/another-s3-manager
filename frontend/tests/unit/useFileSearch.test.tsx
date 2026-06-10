import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useFileSearch } from "@/features/files/hooks/useFileSearch";
import * as filesApi from "@/features/files/api/filesApi";

function wrapper() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

beforeEach(() => vi.restoreAllMocks());

describe("useFileSearch", () => {
  it("does not fetch when the term is empty", () => {
    const spy = vi.spyOn(filesApi, "listFiles");
    renderHook(() => useFileSearch("b", "r", "", ""), { wrapper: wrapper() });
    expect(spy).not.toHaveBeenCalled();
  });

  it("calls listFiles with the search term and exposes the chunk", async () => {
    const spy = vi.spyOn(filesApi, "listFiles").mockResolvedValue({
      directories: [{ name: "4f2a1c", is_directory: true, size: 0 }],
      files: [{ name: "4f2a-note.txt", is_directory: false, size: 3 }],
      truncated: false,
      next_token: null,
    });

    const { result } = renderHook(() => useFileSearch("b", "r", "", "4f2a"), {
      wrapper: wrapper(),
    });

    await waitFor(() => expect(result.current.directories.length).toBe(1));
    expect(spy).toHaveBeenCalledWith("b", "r", "", { search: "4f2a" });
    expect(result.current.files[0].name).toBe("4f2a-note.txt");
    expect(result.current.truncated).toBe(false);
  });

  it("forwards the continuation token on loadMore", async () => {
    const spy = vi
      .spyOn(filesApi, "listFiles")
      .mockResolvedValueOnce({
        directories: [],
        files: [{ name: "p-1", is_directory: false, size: 1 }],
        truncated: true,
        next_token: "tok",
      })
      .mockResolvedValueOnce({
        directories: [],
        files: [{ name: "p-2", is_directory: false, size: 1 }],
        truncated: false,
        next_token: null,
      });

    const { result } = renderHook(() => useFileSearch("b", "r", "", "p-"), {
      wrapper: wrapper(),
    });

    await waitFor(() => expect(result.current.files.length).toBe(1));
    await act(async () => {
      await result.current.loadMore();
    });
    await waitFor(() => expect(result.current.files.length).toBe(2));
    expect(spy).toHaveBeenLastCalledWith("b", "r", "", {
      search: "p-",
      continuationToken: "tok",
    });
  });
});
