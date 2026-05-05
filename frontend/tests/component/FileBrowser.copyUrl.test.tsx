import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/features/files/api/filesApi", () => ({
  listBuckets: vi.fn(),
  listFiles: vi.fn(),
  uploadFile: vi.fn(),
  deleteFile: vi.fn(),
  buildDownloadUrl: (b: string, r: string, p: string) =>
    `/api/buckets/${b}/download?role=${r}&path=${encodeURIComponent(p)}`,
  getPresignedDownloadUrl: vi.fn(),
}));
vi.mock("@/features/files/hooks/useFiles", () => ({
  useFiles: () => ({
    data: {
      files: [{ name: "photo.jpg", is_directory: false, size: 1234 }],
      path: "",
      total_count: 1,
    },
    isLoading: false,
  }),
}));
vi.mock("@/features/files/hooks/useDelete", () => ({
  useDelete: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));
vi.mock("@/features/files/hooks/useUpload", () => ({
  useUpload: () => ({ mutateAsync: vi.fn() }),
}));
vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => ({ data: { disable_deletion: false } }),
}));
vi.mock("@/features/files/hooks/usePresignedUrl", () => ({
  usePresignedUrl: () => ({ data: undefined, isSuccess: false }),
}));

import { FileBrowser } from "@/components/FileBrowser/FileBrowser";
import { getPresignedDownloadUrl } from "@/features/files/api/filesApi";

function renderBrowser() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <MantineProvider>
      <Notifications />
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/r/RoleA/b/my-bucket/p/"]}>
          <Routes>
            <Route
              path="/r/:roleId/b/:bucket/p/*"
              element={<FileBrowser />}
            />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
}

describe("FileBrowser Copy URL", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  it("copies the presigned URL (not the proxy URL) for a single file", async () => {
    vi.mocked(getPresignedDownloadUrl).mockResolvedValueOnce({
      url: "https://signed.example/photo.jpg?X-Amz-Signature=abc",
      expires_at: "2026-05-05T12:00:00+00:00",
    });
    renderBrowser();
    fireEvent.click(screen.getByLabelText("Copy URL"));
    await waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
        "https://signed.example/photo.jpg?X-Amz-Signature=abc",
      ),
    );
    expect(getPresignedDownloadUrl).toHaveBeenCalledWith(
      "my-bucket",
      "RoleA",
      "photo.jpg",
    );
  });
});
