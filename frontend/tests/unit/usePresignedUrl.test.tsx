import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { usePresignedUrl } from "@/features/files/hooks/usePresignedUrl";

vi.mock("@/features/files/api/filesApi", () => ({
  getPresignedDownloadUrl: vi.fn(),
}));

import { getPresignedDownloadUrl } from "@/features/files/api/filesApi";

function makeWrapper() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

describe("usePresignedUrl", () => {
  beforeEach(() => vi.clearAllMocks());

  it("returns the presigned URL when enabled", async () => {
    vi.mocked(getPresignedDownloadUrl).mockResolvedValueOnce({
      url: "https://signed/x",
      expires_at: "2026-05-05T12:00:00+00:00",
      expires_in: 3600,
    });
    const { result } = renderHook(
      () => usePresignedUrl("b", "r", "img.png", true),
      { wrapper: makeWrapper() },
    );
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.url).toBe("https://signed/x");
    expect(getPresignedDownloadUrl).toHaveBeenCalledWith("b", "r", "img.png");
  });

  it("does not fire when enabled=false", async () => {
    const { result } = renderHook(
      () => usePresignedUrl("b", "r", "img.png", false),
      { wrapper: makeWrapper() },
    );
    await new Promise((r) => setTimeout(r, 10));
    expect(result.current.fetchStatus).toBe("idle");
    expect(getPresignedDownloadUrl).not.toHaveBeenCalled();
  });

  it("is keyed on bucket+role+path so different paths cache separately", async () => {
    vi.mocked(getPresignedDownloadUrl)
      .mockResolvedValueOnce({
        url: "https://a",
        expires_at: "2026-05-05T12:00:00+00:00",
        expires_in: 3600,
      })
      .mockResolvedValueOnce({
        url: "https://b",
        expires_at: "2026-05-05T12:00:00+00:00",
        expires_in: 3600,
      });
    const wrapper = makeWrapper();
    const { result: r1 } = renderHook(
      () => usePresignedUrl("b", "r", "a.png", true),
      { wrapper },
    );
    const { result: r2 } = renderHook(
      () => usePresignedUrl("b", "r", "b.png", true),
      { wrapper },
    );
    await waitFor(() => {
      expect(r1.current.isSuccess).toBe(true);
      expect(r2.current.isSuccess).toBe(true);
    });
    expect(r1.current.data?.url).toBe("https://a");
    expect(r2.current.data?.url).toBe("https://b");
  });
});
